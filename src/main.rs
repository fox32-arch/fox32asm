#[macro_use]
extern crate lazy_static;
extern crate pest;
#[macro_use]
extern crate pest_derive;

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fmt::Debug;
use std::fs::{canonicalize, read_to_string, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Mutex;

pub(crate) mod include;
pub(crate) mod instr;
pub(crate) mod parser;
pub(crate) mod util;

use include::include_text_file;
use instr::{
    AssembledInstruction, Condition, InstructionIncDec, InstructionTwo, OperationIncDec, Size,
};
use parser::{
    backpatch::{immediate, perform_backpatching, BackpatchTarget},
    immediate::node_to_immediate_values,
    AstNode,
};
use util::conversion::condition_source_destination_to_byte;
use util::{conversion::instruction_to_byte, format_address_table};

// this is kinda dumb, but oh well !!
lazy_static! {
    static ref SOURCE_PATH: Mutex<PathBuf> = Mutex::new(PathBuf::new());
    static ref CURRENT_SIZE: Mutex<Size> = Mutex::new(Size::Word);
    static ref CURRENT_CONDITION: Mutex<Condition> = Mutex::new(Condition::Always);
    static ref LABEL_TARGETS: Mutex<BTreeMap<String, Vec<BackpatchTarget>>> =
        Mutex::new(BTreeMap::new());
    static ref LABEL_ADDRESSES: Mutex<HashMap<String, (u32, bool)>> = Mutex::new(HashMap::new());
    static ref RELOC_ADDRESSES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
}

//const FXF_CODE_SIZE:   usize = 0x00000004;
//const FXF_CODE_PTR:    usize = 0x00000008;
const FXF_RELOC_SIZE: usize = 0x0000000C;
const FXF_RELOC_PTR: usize = 0x00000010;

// Used by data.fill to store either a known size or the name of a constant
// that defines the size
#[derive(PartialEq, Debug, Clone)]
enum SizeOrLabelName {
    Size(u32),
    Label(String),
}

pub const POISONED_MUTEX_ERR: &str = "failed to lock mutex; possibly poisoined";

fn main() -> anyhow::Result<()> {
    let version_string = format!(
        "fox32asm {} ({})",
        env!("VERGEN_BUILD_SEMVER"),
        env!("VERGEN_GIT_SHA_SHORT")
    );
    println!("{}", version_string);

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <input> <output>", args[0]);
        exit(1);
    }

    let input_file_name = &args[1];
    let output_file_name = &args[2];

    let is_fxf = output_file_name.ends_with(".fxf");
    if is_fxf {
        println!("Generating FXF binary");
    } else {
        println!("Generating raw binary");
    }

    let mut input_file = read_to_string(input_file_name).expect("cannot read file");
    println!("Parsing includes...");
    let mut source_path = canonicalize(input_file_name)?;
    source_path.pop();
    *SOURCE_PATH.lock().expect(POISONED_MUTEX_ERR) = source_path;
    for _ in 0..128 {
        let loop_file = input_file.clone(); // this is a hack to allow modifying input_file from inside the for loop
        for (line_number, text) in loop_file.lines().enumerate() {
            match text.trim() {
                s if s.starts_with("#include \"") => {
                    input_file = include_text_file(line_number, text.trim(), input_file.clone())
                        .ok_or(anyhow::Error::msg(format!(
                            "failed to include text file {input_file}",
                        )))?;
                    break;
                }
                _ => {}
            };
        }
    }

    println!("Parsing file...");
    let ast = match parser::parse(&input_file) {
        Ok(x) => x,
        Err(x) => {
            println!("{:#?}", x);
            exit(1);
        }
    };

    let mut instructions: Vec<AssembledInstruction> = Vec::new();
    let mut current_address: u32 = 0;

    println!("Assembling...");
    let mut optimize = false;
    for mut node in ast {
        node = optimize_node(node, &mut optimize);
        if let AstNode::LabelDefine { name, .. } = node {
            let mut address_table = LABEL_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
            if address_table.get(&name).is_some() {
                // this label already exists, print an error and exit
                println!("Label \"{}\" was defined more than once!", name);
                exit(1);
            }
            address_table.insert(name.clone(), (current_address, false));
            std::mem::drop(address_table);
        } else if let AstNode::Constant { name, address } = node {
            let mut address_table = LABEL_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
            address_table.insert(name.clone(), (address, true));
            std::mem::drop(address_table);
        } else if let AstNode::Origin(origin_address) = node {
            assert!(origin_address > current_address);
            current_address = origin_address;
        } else if let AstNode::OriginPadded(origin_address) = node {
            assert!(origin_address > current_address);
            let difference = (origin_address - current_address) as usize;
            current_address = origin_address;
            instructions.push(vec![0; difference].into());
        } else if let AstNode::DataFill { value, size } = node {
            let size = match size {
                SizeOrLabelName::Size(size) => size,
                SizeOrLabelName::Label(name) => {
                    let address_table = LABEL_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
                    address_table
                        .get(&name)
                        .expect(&format!("Label not found: {}", name))
                        .0
                }
            };
            current_address += size;
            instructions.push(vec![value; size as usize].into());
        } else if let AstNode::IncludedBinary(binary_vec) = node {
            current_address += binary_vec.len() as u32;
            instructions.push(binary_vec.into());
        } else if let AstNode::Optimize(_) = node {
        } else {
            let instruction = assemble_node(node)?;
            instruction.set_address(current_address);
            current_address += instruction.borrow().len() as u32;
            instructions.push(instruction);
        }
    }

    println!("Performing label backpatching...");
    let table = LABEL_TARGETS.lock().expect(POISONED_MUTEX_ERR);
    let address_table = LABEL_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);

    let address_file = format_address_table(&address_table);
    println!("{}", address_file);

    for (name, targets) in table.iter() {
        perform_backpatching(
            targets,
            *address_table
                .get(name)
                .expect(&format!("Label not found: {}", name)),
        );
    }
    std::mem::drop(table);
    std::mem::drop(address_table);

    let mut binary: Vec<u8> = Vec::new();

    // if we're generating a FXF binary, write out the header first
    if is_fxf {
        // magic bytes and version
        binary.push(b'F');
        binary.push(b'X');
        binary.push(b'F');
        binary.push(0);

        let mut code_size = 0;
        for instruction in &instructions {
            code_size += &instruction.borrow().len();
        }

        // code size
        binary.extend_from_slice(&u32::to_le_bytes(code_size as u32));
        // code pointer
        binary.extend_from_slice(&u32::to_le_bytes(0x14)); // code starts after the header

        // reloc table size
        binary.extend_from_slice(&u32::to_le_bytes(0));
        // reloc table pointer
        binary.extend_from_slice(&u32::to_le_bytes(0));
    }

    for instruction in instructions {
        binary.extend_from_slice(&(instruction.borrow())[..]);
    }

    // if we're generating a FXF binary, write the reloc table
    if is_fxf {
        // first get the current pointer to where we are in the binary
        let reloc_ptr_bytes = u32::to_le_bytes(binary.len() as u32);

        // write the reloc addresses to the end of the binary
        let reloc_table = &*RELOC_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
        let mut reloc_table_size = 0;
        for address in reloc_table {
            let address_bytes = u32::to_le_bytes(*address);
            binary.extend_from_slice(&address_bytes);
            reloc_table_size += 4;
        }

        // write the reloc size to the FXF header
        let reloc_table_size_bytes = u32::to_le_bytes(reloc_table_size);
        binary[FXF_RELOC_SIZE] = reloc_table_size_bytes[0];
        binary[FXF_RELOC_SIZE + 1] = reloc_table_size_bytes[1];
        binary[FXF_RELOC_SIZE + 2] = reloc_table_size_bytes[2];
        binary[FXF_RELOC_SIZE + 3] = reloc_table_size_bytes[3];

        // write the reloc pointer to the FXF header
        binary[FXF_RELOC_PTR] = reloc_ptr_bytes[0];
        binary[FXF_RELOC_PTR + 1] = reloc_ptr_bytes[1];
        binary[FXF_RELOC_PTR + 2] = reloc_ptr_bytes[2];
        binary[FXF_RELOC_PTR + 3] = reloc_ptr_bytes[3];
    }

    println!(
        "Final binary size: {} bytes = {:.2} KiB = {:.2} MiB",
        binary.len(),
        binary.len() / 1024,
        binary.len() / 1048576
    );

    let mut output_file = File::create(output_file_name)?;
    output_file.write_all(&binary)?;

    Ok(())
}

fn assemble_node(node: AstNode) -> anyhow::Result<AssembledInstruction> {
    // if this is data, don't interpret it as an instruction
    match node {
        AstNode::DataByte(byte) => {
            return Ok(vec![byte].into());
        }
        AstNode::DataHalf(half) => {
            return Ok(half.to_le_bytes().into());
        }
        AstNode::DataWord(word) => {
            return Ok(word.to_le_bytes().into());
        }
        AstNode::DataStr(string) => {
            return Ok(string.as_bytes().into());
        }
        AstNode::DataStrZero(string) => {
            let mut bytes: Vec<u8> = string.as_bytes().into();
            bytes.push(0);
            return Ok(bytes.into());
        }
        AstNode::LabelOperand {
            name,
            size,
            is_relative,
        } => {
            // label is used on its own, not as an operand:
            // LabelOperand was previously only checked as part of operands
            let instruction = AssembledInstruction::new();
            immediate::generate_backpatch(&name, size, &instruction, is_relative)?;
            return Ok(instruction);
        }
        _ => {}
    }

    let mut instruction_data: Vec<u8> = Vec::new();

    let condition_source_destination = condition_source_destination_to_byte(&node);
    instruction_data.push(condition_source_destination);
    instruction_data.push(instruction_to_byte(&node));

    let instruction: AssembledInstruction = instruction_data.into();

    //0x80 bit determines if we need to write the pointer offsets or not
    node_to_immediate_values(
        &node,
        &instruction,
        condition_source_destination & 0x80 != 0,
    )?;

    Ok(instruction)
}

// fn node_to_vec(node: AstNode) -> Vec<u8> {
//     let mut vec = Vec::<u8>::new();
//     let instruction = instruction_to_byte(&node);
//     let condition_source_destination = condition_source_destination_to_byte(&node);
//     vec.push(condition_source_destination);
//     vec.push(instruction);
//     node_to_immediate_values(&node, &mut vec);
//     vec
// }
fn node_value(node: &AstNode) -> Option<u32> {
    match *node {
        AstNode::Immediate16(n) => Some(n as u32),
        AstNode::Immediate32(n) => Some(n),
        AstNode::Immediate8(n) => Some(n as u32),
        _ => None,
    }
}
fn optimize_node(node: AstNode, enabled: &mut bool) -> AstNode {
    if let AstNode::Optimize(value) = node {
        *enabled = value;
    }
    if *enabled {
        match node {
            AstNode::OperationTwo(mut n) => {
                let v = node_value(&n.rhs);
                if let Some(v) = v {
                    match n.instruction {
                        InstructionTwo::Add => match v {
                            1 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Inc,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(0)),
                                })
                            }
                            2 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Inc,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(1)),
                                })
                            }
                            4 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Inc,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(2)),
                                })
                            }
                            8 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Inc,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(3)),
                                })
                            }
                            _ => (),
                        },
                        InstructionTwo::Sub => match v {
                            1 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Dec,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(0)),
                                })
                            }
                            2 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Dec,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(1)),
                                })
                            }
                            4 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Dec,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(2)),
                                })
                            }
                            8 => {
                                return AstNode::OperationIncDec(OperationIncDec {
                                    size: n.size,
                                    condition: n.condition,
                                    instruction: InstructionIncDec::Dec,
                                    lhs: n.lhs,
                                    rhs: Box::new(AstNode::Immediate8(3)),
                                })
                            }
                            _ => (),
                        },
                        InstructionTwo::Mov => {
                            if let Size::Word = n.size {
                                if let AstNode::Register(_) = *n.lhs {
                                    if v <= 0xff {
                                        n.size = Size::Byte;
                                        n.instruction = InstructionTwo::Movz;
                                        n.rhs = Box::new(AstNode::Immediate8(v as u8));
                                    } else if v <= 0xffff {
                                        n.size = Size::Half;
                                        n.instruction = InstructionTwo::Movz;
                                        n.rhs = Box::new(AstNode::Immediate16(v as u16));
                                    }
                                }
                            }
                        }
                        InstructionTwo::Mul => {
                            if let Size::Word = n.size {
                                if v.is_power_of_two() {
                                    n.instruction = InstructionTwo::Sla;
                                    n.rhs = Box::new(AstNode::Immediate8(v.trailing_zeros() as u8));
                                }
                            }
                        }
                        InstructionTwo::Idiv => {
                            if let Size::Word = n.size {
                                if v.is_power_of_two() {
                                    n.instruction = InstructionTwo::Sra;
                                    n.rhs = Box::new(AstNode::Immediate8(v.trailing_zeros() as u8));
                                }
                            }
                        }
                        InstructionTwo::Div => {
                            if let Size::Word = n.size {
                                if v.is_power_of_two() {
                                    n.instruction = InstructionTwo::Srl;
                                    n.rhs = Box::new(AstNode::Immediate8(v.trailing_zeros() as u8));
                                }
                            }
                        }
                        // InstructionTwo::Sla
                        // | InstructionTwo::Srl | InstructionTwo::Sra
                        // | InstructionTwo::Bcl | InstructionTwo::Bse
                        // | InstructionTwo::Bts
                        // | InstructionTwo::Ror | InstructionTwo::Rol
                        // => {
                        //     n.rhs = Box::new(AstNode::Immediate8(v as u8));

                        // }
                        _ => (),
                    }
                }

                AstNode::OperationTwo(n)
            }
            _ => node,
        }
    } else {
        node
    }
}
