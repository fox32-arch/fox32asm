#[macro_use]
extern crate lazy_static;
extern crate pest;
#[macro_use]
extern crate pest_derive;

use pest::error::Error;
use pest::Parser;
use core::panic;
use std::collections::HashMap;
use std::env;
use std::fs::{canonicalize, read, read_to_string, File};
use std::fmt::Debug;
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::cell::{Cell, RefCell};
use std::sync::Mutex;
use std::io::Write;
use std::ops::Deref;

#[derive(Parser)]
#[grammar = "fox32.pest"]
struct Fox32Parser;

// this is kinda dumb, but oh well !!
lazy_static! {
    static ref SOURCE_PATH: Mutex<PathBuf> = Mutex::new(PathBuf::new());
    static ref CURRENT_SIZE: Mutex<Size> = Mutex::new(Size::Word);
    static ref CURRENT_CONDITION: Mutex<Condition> = Mutex::new(Condition::Always);
    static ref LABEL_TARGETS: Mutex<HashMap<String, Vec<BackpatchTarget>>> = Mutex::new(HashMap::new());
    static ref LABEL_ADDRESSES: Mutex<HashMap<String, (u32, bool)>> = Mutex::new(HashMap::new());
    static ref RELOC_ADDRESSES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
}

//const FXF_CODE_SIZE:   usize = 0x00000004;
//const FXF_CODE_PTR:    usize = 0x00000008;
const FXF_RELOC_SIZE:  usize = 0x0000000C;
const FXF_RELOC_PTR:   usize = 0x00000010;

#[derive(Debug, Clone)]
struct BackpatchTarget {
    index: usize,
    size: Size,
    is_relative: bool,
    instruction: AssembledInstruction,
}

impl BackpatchTarget {
    fn new(instruction: &AssembledInstruction, index: usize, size: Size, is_relative: bool) -> BackpatchTarget {
        Self {
            index, is_relative, size,
            instruction: instruction.clone(),
        }
    }

    fn write(&self, size: Size, address: u32) {
        let ref instruction = self.instruction;
        let mut instruction_data = instruction.borrow_mut();

        let address_bytes =
            if self.is_relative {
                (address as i32 - self.instruction.get_address() as i32).to_le_bytes()
            } else {
                address.to_le_bytes()
            };

        match size {
            Size::Byte => instruction_data[self.index] = address_bytes[0],
            Size::Half => {
                instruction_data[self.index]     = address_bytes[0];
                instruction_data[self.index + 1] = address_bytes[1];
            },
            Size::Word => {
                instruction_data[self.index]     = address_bytes[0];
                instruction_data[self.index + 1] = address_bytes[1];
                instruction_data[self.index + 2] = address_bytes[2];
                instruction_data[self.index + 3] = address_bytes[3];
            }
        }
    }

    fn get_backpatch_location(&self) -> u32 {
        self.instruction.get_address() + self.index as u32
    }
}

fn perform_backpatching(targets: &Vec<BackpatchTarget>, address: (u32, bool)) {
    for target in targets {
        target.write(target.size, address.0);

        // if this label isn't const or relative, then add it to the reloc table for FXF
        if !address.1 && !target.is_relative {
            let mut reloc_table = RELOC_ADDRESSES.lock().unwrap();
            reloc_table.push(target.get_backpatch_location());
        }
    }
}

#[derive(Debug, Clone, Default)]
struct AssembledInstruction {
    value: Rc<RefCell<Vec<u8>>>,
    address: Rc<Cell<u32>>,
}

impl AssembledInstruction {
    fn new() -> Self {
        Self {
            value: Rc::default(),
            address: Rc::default(),
        }
    }

    fn get_address(&self) -> u32 {
        self.address.get()
    }
    fn set_address(&self, address: u32) {
        self.address.set(address);
    }
}

impl From<Vec<u8>> for AssembledInstruction {
    fn from(data: Vec<u8>) -> Self {
        Self {
            value: Rc::new(RefCell::new(data)),
            address: Rc::default(),
        }
    }
}

impl From<&[u8]> for AssembledInstruction {
    fn from(data: &[u8]) -> Self {
        Vec::from(data).into()
    }
}

impl<const N: usize> From<[u8; N]> for AssembledInstruction {
    fn from(data: [u8; N]) -> Self {
        (&data[..]).into()
    }
}

impl Deref for AssembledInstruction {
    type Target = RefCell<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

unsafe impl Send for AssembledInstruction {}
unsafe impl Sync for AssembledInstruction {}

#[derive(PartialEq, Debug, Clone, Copy)]
enum InstructionZero {
    // no operands
    Nop,
    Halt,
    Brk,
    Ret,
    Reti,
    Ise,
    Icl,
    Mse,
    Mcl,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum InstructionOne {
    // one operand
    Inc,
    Dec,
    Not,
    Jmp,
    Call,
    Loop,
    Rjmp,
    Rcall,
    Rloop,
    Push,
    Pop,
    Int,
    Tlb,
    Flp,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum InstructionTwo {
    // two operands
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Sla,
    Sra,
    Srl,
    Rol,
    Ror,
    Bse,
    Bcl,
    Bts,
    Cmp,
    Mov,
    Movz,
    Rta,
    In,
    Out,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum Size {
    Byte,
    Half,
    Word,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum Condition {
    Always,
    Zero,
    NotZero,
    Carry,
    NotCarry,
    GreaterThan,
    // GreaterThanEqualTo is equivalent to NotCarry
    // LessThan is equivalent to Carry
    LessThanEqualTo,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum LabelKind {
    Internal,
    External,
    Global,
}

#[derive(PartialEq, Debug, Clone)]
enum AstNode {
    OperationZero {
        condition: Condition,
        instruction: InstructionZero,
    },
    OperationOne {
        size: Size,
        condition: Condition,
        instruction: InstructionOne,
        operand: Box<AstNode>,
    },
    OperationTwo {
        size: Size,
        condition: Condition,
        instruction: InstructionTwo,
        lhs: Box<AstNode>,
        rhs: Box<AstNode>,
    },

    Immediate8(u8),
    Immediate16(u16),
    Immediate32(u32),
    Register(u8),
    ImmediatePointer(u32),
    RegisterPointer(u8),

    Constant {
        name: String,
        address: u32,
    },

    LabelDefine {
        name: String,
        kind: LabelKind,
    },
    LabelOperand {
        name: String,
        size: Size,
        is_relative: bool,
    },
    LabelOperandPointer {
        name: String,
        is_relative: bool,
    },

    DataByte(u8),
    DataHalf(u16),
    DataWord(u32),
    DataStr(String),
    DataFill {
        value: u8,
        size: u32,
    },

    IncludedBinary(Vec<u8>),

    Origin(u32),
    OriginPadded(u32),
}

fn format_address_table(m: &HashMap<String, (u32, bool)>) -> String {
    let mut v: Vec<(&String, &u32)> = Vec::new();
    for i in m.into_iter() {
        v.push((i.0, &i.1.0));
    }
    v.sort_by(|(_, v1), (_, v2)| u32::cmp(v1, v2));
    v.iter().map(|(k, v)| format!("{:#010X?} :: {}", v, k)).collect::<Vec<String>>().join("\n")
}

fn main() {
    let version_string = format!("fox32asm {} ({})", env!("VERGEN_BUILD_SEMVER"), env!("VERGEN_GIT_SHA_SHORT"));
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
    let mut source_path = canonicalize(&input_file_name).unwrap();
    source_path.pop();
    *SOURCE_PATH.lock().unwrap() = source_path;
    for _ in 0..128 {
        let loop_file = input_file.clone(); // this is a hack to allow modifying input_file from inside the for loop
        for (line_number, text) in loop_file.lines().enumerate() {
            match text.trim() {
                s if s.starts_with("#include \"") => {
                    input_file = include_text_file(line_number, text.trim(), input_file);
                    break;
                },
                _ => {}
            };
        }
    }

    println!("Parsing file...");
    let ast = parse(&input_file);

    let mut instructions: Vec<AssembledInstruction> = Vec::new();
    let mut current_address: u32 = 0;

    println!("Assembling...");
    for node in ast.unwrap() {
        if let AstNode::LabelDefine {name, ..} = node {
            let mut address_table = LABEL_ADDRESSES.lock().unwrap();
            address_table.insert(name.clone(), (current_address, false));
            std::mem::drop(address_table);
        } else if let AstNode::Constant {name, address} = node {
            let mut address_table = LABEL_ADDRESSES.lock().unwrap();
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
        } else if let AstNode::DataFill {value, size} = node {
            current_address += size;
            instructions.push(vec![value; size as usize].into());
        } else if let AstNode::IncludedBinary(binary_vec) = node {
            current_address += binary_vec.len() as u32;
            instructions.push(binary_vec.into());
        } else {
            let instruction = assemble_node(node);
            instruction.set_address(current_address);
            current_address += instruction.borrow().len() as u32;
            instructions.push(instruction);
        }
    }

    println!("Performing label backpatching...");
    let table = LABEL_TARGETS.lock().unwrap();
    let address_table = LABEL_ADDRESSES.lock().unwrap();

    let address_file = format_address_table(&address_table);
    println!("{}", address_file);

    for (name, targets) in table.iter() {
        perform_backpatching(targets, *address_table.get(name).expect(&format!("Label not found: {}", name)));
    }
    std::mem::drop(table);
    std::mem::drop(address_table);

    let mut binary: Vec<u8> = Vec::new();

    // if we're generating a FXF binary, write out the header first
    if is_fxf {
        // magic bytes and version
        binary.push('F' as u8);
        binary.push('X' as u8);
        binary.push('F' as u8);
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
        let reloc_table = &*RELOC_ADDRESSES.lock().unwrap();
        let mut reloc_table_size = 0;
        for address in reloc_table {
            let address_bytes = u32::to_le_bytes(*address);
            binary.extend_from_slice(&address_bytes);
            reloc_table_size += 4;
        }

        // write the reloc size to the FXF header
        let reloc_table_size_bytes = u32::to_le_bytes(reloc_table_size);
        binary[FXF_RELOC_SIZE]     = reloc_table_size_bytes[0];
        binary[FXF_RELOC_SIZE + 1] = reloc_table_size_bytes[1];
        binary[FXF_RELOC_SIZE + 2] = reloc_table_size_bytes[2];
        binary[FXF_RELOC_SIZE + 3] = reloc_table_size_bytes[3];

        // write the reloc pointer to the FXF header
        binary[FXF_RELOC_PTR]     = reloc_ptr_bytes[0];
        binary[FXF_RELOC_PTR + 1] = reloc_ptr_bytes[1];
        binary[FXF_RELOC_PTR + 2] = reloc_ptr_bytes[2];
        binary[FXF_RELOC_PTR + 3] = reloc_ptr_bytes[3];
    }

    println!("Final binary size: {} bytes = {:.2} KiB = {:.2} MiB", binary.len(), binary.len() / 1024, binary.len() / 1048576);

    let mut output_file = File::create(output_file_name).unwrap();
    output_file.write_all(&binary).unwrap();
}

fn include_text_file(line_number: usize, text: &str, input_file: String) -> String {
    //println!("{}, {}", line_number, text);
    let path_start_index = text.find("\"").unwrap() + 1;
    let path_end_index = text.len() - 1;
    let path_string = &text[path_start_index..path_end_index];
    //let path = canonicalize(path_string).expect(&format!("failed to include file \"{}\"", path_string));

    let mut source_path = SOURCE_PATH.lock().unwrap().clone();
    source_path.push(path_string);

    println!("Including file as text data: {:#?}", source_path.file_name().expect("invalid filename"));

    let mut start_of_original_file = String::new();
    for (i, text) in input_file.lines().enumerate() {
        if i < line_number {
            start_of_original_file.push_str(text);
            start_of_original_file.push('\n');
        }
    }

    let mut included_file = read_to_string(source_path).expect("failed to include file");
    included_file.push('\n');

    let mut end_of_original_file = String::new();
    for (i, text) in input_file.lines().enumerate() {
        if i > line_number {
            end_of_original_file.push_str(text);
            end_of_original_file.push('\n');
        }
    }

    let mut final_file = String::new();

    final_file.push_str(&start_of_original_file);
    final_file.push_str(&included_file);
    final_file.push_str(&end_of_original_file);
    final_file
}

fn include_binary_file(pair: pest::iterators::Pair<Rule>) -> AstNode {
    let path_string = pair.into_inner().next().unwrap().as_str().trim();
    //let path = canonicalize(path_string).expect(&format!("failed to include file \"{}\"", path_string));

    let mut source_path = SOURCE_PATH.lock().unwrap().clone();
    source_path.push(path_string);

    println!("Including file as binary data: {:#?}", source_path.file_name().expect("invalid filename"));

    let binary = read(source_path).expect("failed to include file");

    AstNode::IncludedBinary(binary)
}

fn parse(source: &str) -> Result<Vec<AstNode>, Error<Rule>> {
    let mut ast = vec![];
    let pairs = Fox32Parser::parse(Rule::assembly, source).expect("parse was unsuccessful");

    for pair in pairs.peek().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::EOI => break,
            _ => ast.push(build_ast_from_expression(pair)),
        }
    }

    Ok(ast)
}

fn build_ast_from_expression(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("{:#?}\n\n", pair); // debug

    let pair_rule = pair.as_rule();
    let mut inner_pair = pair.into_inner();
    *CURRENT_CONDITION.lock().unwrap() = Condition::Always;
    let mut is_pointer = false;
    match inner_pair.peek().unwrap().as_rule() {
        Rule::condition => {
            *CURRENT_CONDITION.lock().unwrap() = parse_condition(&inner_pair.peek().unwrap());
            inner_pair.next().unwrap(); // jump to the next instruction pair after the condition
        }
        Rule::operand_value_ptr => {
            is_pointer = true;
        }
        _ => {}
    }

    match pair_rule {
        Rule::assembly => build_ast_from_expression(inner_pair.next().unwrap()),
        Rule::instruction => parse_instruction(inner_pair.next().unwrap()),
        Rule::operand => parse_operand(inner_pair.next().unwrap(), is_pointer),
        Rule::constant => parse_constant(inner_pair),
        Rule::label => parse_label(inner_pair.next().unwrap(), inner_pair.next()),
        Rule::data => parse_data(inner_pair.next().unwrap()),
        Rule::origin => parse_origin(inner_pair.next().unwrap()),
        Rule::include_bin => include_binary_file(inner_pair.next().unwrap()),
        _ => todo!("{:#?}", pair_rule),
    }
}

fn parse_constant(pairs: pest::iterators::Pairs<Rule>) -> AstNode {
    *CURRENT_SIZE.lock().unwrap() = Size::Word;
    let mut pairs = pairs;
    let constant_name = pairs.next().unwrap().into_inner().next().unwrap().as_str();
    let operand_pair = pairs.next().unwrap();
    let operand_ast = parse_operand(operand_pair, false);

    if let AstNode::Immediate32(address) = operand_ast {
        AstNode::Constant {
            name: constant_name.to_string(),
            address,
        }
    } else {
        panic!("Constant must be an immediate value");
    }
}

fn parse_label(pair: pest::iterators::Pair<Rule>, next_pair: Option<pest::iterators::Pair<Rule>>) -> AstNode {
    let mut name_pair = pair.clone();
    let kind = match pair.as_rule() {
        Rule::label_kind => {
            let pair_inner = pair.clone().into_inner().next().unwrap();
            name_pair = next_pair.unwrap();
            match pair_inner.as_rule() {
                Rule::label_external => LabelKind::External,
                Rule::label_global => LabelKind::Global,
                _ => unreachable!()
            }
        },
        _ => LabelKind::Internal,
    };
    let node = AstNode::LabelDefine {name: name_pair.as_str().to_string(), kind};
    node
}

fn parse_data(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("{:#?}", pair);
    match pair.as_rule() {
        Rule::data_byte => {
            let ast = parse_operand(pair.into_inner().next().unwrap(), false);
            let byte = {
                if let AstNode::Immediate32(word) = ast {
                    word as u8
                } else {
                    unreachable!()
                }
            };
            AstNode::DataByte(byte)
        },
        Rule::data_half => {
            let ast = parse_operand(pair.into_inner().next().unwrap(), false);
            let word = {
                if let AstNode::Immediate32(word) = ast {
                    word as u16
                } else {
                    unreachable!()
                }
            };
            AstNode::DataHalf(word)
        },
        Rule::data_word => {
            match parse_operand(pair.into_inner().next().unwrap(), false) {
                AstNode::Immediate32(word) => AstNode::DataWord(word),
                AstNode::LabelOperand {name, size, is_relative} => AstNode::LabelOperand {name, size, is_relative},
                _ => unreachable!(),
            }
        },
        Rule::data_str => {
            let string = pair.into_inner().next().unwrap().into_inner().next().unwrap().as_str();
            AstNode::DataStr(string.to_string())
        },
        Rule::data_fill => {
            let value = {
                let ast = parse_operand(pair.clone().into_inner().next().unwrap(), false);
                if let AstNode::Immediate32(word) = ast {
                    word as u8
                } else {
                    unreachable!()
                }
            };
            let size = {
                let ast = parse_operand(pair.into_inner().nth(1).unwrap(), false);
                if let AstNode::Immediate32(word) = ast {
                    word
                } else {
                    unreachable!()
                }
            };
            AstNode::DataFill {value, size}
        },
        _ => panic!("Unsupported data: {}", pair.as_str()),
    }
}

fn parse_origin(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("{:#?}", pair);
    match pair.as_rule() {
        Rule::origin_no_padding => {
            let ast = parse_operand(pair.into_inner().next().unwrap(), false);
            let address = {
                if let AstNode::Immediate32(word) = ast {
                    word
                } else {
                    unreachable!()
                }
            };
            AstNode::Origin(address)
        },
        Rule::origin_padding => {
            let ast = parse_operand(pair.into_inner().next().unwrap(), false);
            let address = {
                if let AstNode::Immediate32(word) = ast {
                    word
                } else {
                    unreachable!()
                }
            };
            AstNode::OriginPadded(address)
        },
        _ => panic!("Unsupported origin: {}", pair.as_str()),
    }
}

fn parse_size(pair: &pest::iterators::Pair<Rule>) -> Size {
    match pair.as_str() {
        ".8" => Size::Byte,
        ".16" => Size::Half,
        ".32" => Size::Word,
        _ => panic!("Unsupported size: {}", pair.as_str()),
    }
}

fn parse_condition(pair: &pest::iterators::Pair<Rule>) -> Condition {
    match pair.as_str() {
        "ifz" => Condition::Zero,
        "ifnz" => Condition::NotZero,
        "ifc" => Condition::Carry,
        "ifnc" => Condition::NotCarry,
        "ifgt" => Condition::GreaterThan,
        "ifgteq" => Condition::NotCarry,
        "iflt" => Condition::Carry,
        "iflteq" => Condition::LessThanEqualTo,
        _ => panic!("Unsupported condition: {}", pair.as_str()),
    }
}

fn parse_instruction(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("parse_instruction: {:#?}", pair); // debug
    let mut size = Size::Word;
    let condition = *CURRENT_CONDITION.lock().unwrap();
    match pair.as_rule() {
        Rule::instruction_conditional => {
            let mut inner_pair = pair.into_inner();
            let instruction_conditional_pair = inner_pair.next().unwrap();
            match instruction_conditional_pair.as_rule() {
                Rule::instruction_zero => parse_instruction_zero(instruction_conditional_pair, condition),
                Rule::instruction_one => {
                    if inner_pair.peek().unwrap().as_rule() == Rule::size {
                        size = parse_size(&inner_pair.next().unwrap());
                    }
                    *CURRENT_SIZE.lock().unwrap() = size;
                    let operand = inner_pair.next().unwrap();
                    let operand_ast = build_ast_from_expression(operand);
                    parse_instruction_one(instruction_conditional_pair, operand_ast, size, condition)
                }
                Rule::instruction_two => {
                    if inner_pair.peek().unwrap().as_rule() == Rule::size {
                        size = parse_size(&inner_pair.next().unwrap());
                    }
                    *CURRENT_SIZE.lock().unwrap() = size;
                    let lhs = inner_pair.next().unwrap();
                    let rhs = inner_pair.next().unwrap();
                    let lhs_ast = build_ast_from_expression(lhs);
                    let rhs_ast = build_ast_from_expression(rhs);
                    parse_instruction_two(instruction_conditional_pair, lhs_ast, rhs_ast, size, condition)
                }
                _ => todo!(),
            }
        }
        _ => panic!("Unsupported instruction type: {:#?}", pair.as_rule()),
    }
}

fn remove_underscores(input: &str) -> String {
    String::from_iter(input.chars().filter(|c| *c != '_'))
}

fn parse_operand(mut pair: pest::iterators::Pair<Rule>, is_pointer: bool) -> AstNode {
    //println!("parse_operand: {:#?}", pair); // debug
    let size = *CURRENT_SIZE.lock().unwrap();
    if is_pointer {
        // skip past the operand_value_ptr pair and look at its operand_value rule
        pair = pair.into_inner().next().unwrap();
    }
    match pair.as_rule() {
        Rule::operand_value => {
            let mut inner_pair = pair.into_inner();
            let operand_value_pair = inner_pair.next().unwrap();
            match operand_value_pair.as_rule() {
                Rule::immediate_bin => {
                    let body_bin_str = operand_value_pair.into_inner().next().unwrap().as_str();
                    let immediate = u32::from_str_radix(&remove_underscores(body_bin_str), 2).unwrap();
                    if is_pointer {
                        AstNode::ImmediatePointer(immediate)
                    } else {
                        match size {
                            Size::Byte => AstNode::Immediate8(immediate as u8),
                            Size::Half => AstNode::Immediate16(immediate as u16),
                            Size::Word => AstNode::Immediate32(immediate),
                        }
                    }
                }
                Rule::immediate_hex => {
                    let body_hex_str = operand_value_pair.into_inner().next().unwrap().as_str();
                    let immediate = u32::from_str_radix(&remove_underscores(body_hex_str), 16).unwrap();
                    if is_pointer {
                        AstNode::ImmediatePointer(immediate)
                    } else {
                        match size {
                            Size::Byte => AstNode::Immediate8(immediate as u8),
                            Size::Half => AstNode::Immediate16(immediate as u16),
                            Size::Word => AstNode::Immediate32(immediate),
                        }
                    }
                }
                Rule::immediate_dec => {
                    let body_dec_str = operand_value_pair.into_inner().next().unwrap().as_str();
                    let immediate = remove_underscores(body_dec_str).parse::<u32>().unwrap();
                    if is_pointer {
                        AstNode::ImmediatePointer(immediate)
                    } else {
                        match size {
                            Size::Byte => AstNode::Immediate8(immediate as u8),
                            Size::Half => AstNode::Immediate16(immediate as u16),
                            Size::Word => AstNode::Immediate32(immediate),
                        }
                    }
                }
                Rule::immediate_char => {
                    let body_char_str = operand_value_pair.into_inner().next().unwrap().as_str();
                    let immediate = body_char_str.chars().nth(0).unwrap() as u8 as u32;
                    if is_pointer {
                        AstNode::ImmediatePointer(immediate)
                    } else {
                        match size {
                            Size::Byte => AstNode::Immediate8(immediate as u8),
                            Size::Half => AstNode::Immediate16(immediate as u16),
                            Size::Word => AstNode::Immediate32(immediate),
                        }
                    }
                }
                Rule::register => {
                    let register_num_pair = operand_value_pair.into_inner().next().unwrap();
                    let register_num = if register_num_pair.as_str() == "sp" { 32 }
                    else if register_num_pair.as_str() == "esp" { 33 }
                    else { register_num_pair.as_str().parse::<u8>().unwrap() };
                    if register_num > 33 { panic!("register number out of range"); }
                    if is_pointer {
                        AstNode::RegisterPointer(register_num)
                    } else {
                        AstNode::Register(register_num)
                    }
                }
                Rule::label_name => {
                    if is_pointer {
                        AstNode::LabelOperandPointer {
                            name: operand_value_pair.as_str().to_string(),
                            is_relative: false,
                        }
                    } else {
                        AstNode::LabelOperand {
                            name: operand_value_pair.as_str().to_string(),
                            size,
                            is_relative: false,
                        }
                    }
                }
                _ => todo!(),
            }
        }
        _ => panic!(),
    }
}

fn parse_instruction_zero(pair: pest::iterators::Pair<Rule>, condition: Condition) -> AstNode {
    AstNode::OperationZero {
        condition: condition,
        instruction: match pair.as_str() {
            "nop"  => InstructionZero::Nop,
            "halt" => InstructionZero::Halt,
            "brk"  => InstructionZero::Brk,
            "ret"  => InstructionZero::Ret,
            "reti" => InstructionZero::Reti,
            "ise"  => InstructionZero::Ise,
            "icl"  => InstructionZero::Icl,
            "mse"  => InstructionZero::Mse,
            "mcl"  => InstructionZero::Mcl,
            _ => panic!("Unsupported conditional instruction (zero): {}", pair.as_str()),
        },
    }
}

fn parse_instruction_one(pair: pest::iterators::Pair<Rule>, mut operand: AstNode, size: Size, condition: Condition) -> AstNode {
    AstNode::OperationOne {
        size: size,
        condition: condition,
        instruction: match pair.as_str() {
            "inc"   => InstructionOne::Inc,
            "dec"   => InstructionOne::Dec,
            "not"   => InstructionOne::Not,
            "jmp"   => InstructionOne::Jmp,
            "call"  => InstructionOne::Call,
            "loop"  => InstructionOne::Loop,
            "rjmp"  => {
                match &mut operand {
                    &mut AstNode::LabelOperand        {ref mut is_relative, ..} |
                    &mut AstNode::LabelOperandPointer {ref mut is_relative, ..} => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionOne::Rjmp
            },
            "rcall" => {
                match &mut operand {
                    &mut AstNode::LabelOperand        {ref mut is_relative, ..} |
                    &mut AstNode::LabelOperandPointer {ref mut is_relative, ..} => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionOne::Rcall
            },
            "rloop" => {
                match &mut operand {
                    &mut AstNode::LabelOperand        {ref mut is_relative, ..} |
                    &mut AstNode::LabelOperandPointer {ref mut is_relative, ..} => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionOne::Rloop
            },
            "push"  => InstructionOne::Push,
            "pop"   => InstructionOne::Pop,
            "int"   => InstructionOne::Int,
            "tlb"   => InstructionOne::Tlb,
            "flp"   => InstructionOne::Flp,
            _ => panic!("Unsupported conditional instruction (one): {}", pair.as_str()),
        },
        operand: Box::new(operand),
    }
}

fn parse_instruction_two(pair: pest::iterators::Pair<Rule>, mut lhs: AstNode, mut rhs: AstNode, size: Size, condition: Condition) -> AstNode {
    AstNode::OperationTwo {
        size: size,
        condition: condition,
        instruction: match pair.as_str() {
            "add"  => InstructionTwo::Add,
            "sub"  => InstructionTwo::Sub,
            "mul"  => InstructionTwo::Mul,
            "div"  => InstructionTwo::Div,
            "rem"  => InstructionTwo::Rem,
            "and"  => InstructionTwo::And,
            "or"   => InstructionTwo::Or,
            "xor"  => InstructionTwo::Xor,
            "sla"  => InstructionTwo::Sla,
            "sra"  => InstructionTwo::Sra,
            "srl"  => InstructionTwo::Srl,
            "rol"  => InstructionTwo::Rol,
            "ror"  => InstructionTwo::Ror,
            "bse"  => InstructionTwo::Bse,
            "bcl"  => InstructionTwo::Bcl,
            "bts"  => InstructionTwo::Bts,
            "cmp"  => InstructionTwo::Cmp,
            "mov"  => InstructionTwo::Mov,
            "movz" => InstructionTwo::Movz,
            "rta"  => {
                match &mut lhs {
                    &mut AstNode::LabelOperand        {ref mut is_relative, ..} |
                    &mut AstNode::LabelOperandPointer {ref mut is_relative, ..} => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                match &mut rhs {
                    &mut AstNode::LabelOperand        {ref mut is_relative, ..} |
                    &mut AstNode::LabelOperandPointer {ref mut is_relative, ..} => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionTwo::Rta
            }
            "in"   => InstructionTwo::In,
            "out"  => InstructionTwo::Out,
            _ => panic!("Unsupported conditional instruction (two): {}", pair.as_str()),
        },
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn assemble_node(node: AstNode) -> AssembledInstruction {
    // if this is data, don't interpret it as an instruction
    match node {
        AstNode::DataByte(byte) => {
            return vec![byte].into();
        },
        AstNode::DataHalf(half) => {
            return half.to_le_bytes().into();
        },
        AstNode::DataWord(word) => {
            return word.to_le_bytes().into();
        },
        AstNode::DataStr(string) => {
            return string.as_bytes().into();
        },
        AstNode::LabelOperand {name, size, is_relative} => {
            // label is used on its own, not as an operand:
            // LabelOperand was previously only checked as part of operands
            let instruction = AssembledInstruction::new();
            generate_backpatch_immediate(&name, &size, &instruction, is_relative);
            return instruction;
        },
        _ => {}
    }

    let mut instruction_data: Vec<u8> = Vec::new();

    instruction_data.push(condition_source_destination_to_byte(&node));
    instruction_data.push(instruction_to_byte(&node));

    let mut instruction: AssembledInstruction = instruction_data.into();

    node_to_immediate_values(&node, &mut instruction);

    instruction
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

fn size_to_byte(size: &Size) -> u8 {
    match size {
        Size::Byte => 0b00000000,
        Size::Half => 0b01000000,
        Size::Word => 0b10000000,
    }
}

fn instruction_to_byte(node: &AstNode) -> u8 {
    match node {
        AstNode::OperationZero {instruction, ..} => {
            match instruction {
                InstructionZero::Nop  => 0x00 | size_to_byte(&Size::Word),
                InstructionZero::Halt => 0x10 | size_to_byte(&Size::Word),
                InstructionZero::Brk  => 0x20 | size_to_byte(&Size::Word),
                InstructionZero::Ret  => 0x2A | size_to_byte(&Size::Word),
                InstructionZero::Reti => 0x3A | size_to_byte(&Size::Word),
                InstructionZero::Ise  => 0x0C | size_to_byte(&Size::Word),
                InstructionZero::Icl  => 0x1C | size_to_byte(&Size::Word),
                InstructionZero::Mse  => 0x0D | size_to_byte(&Size::Word),
                InstructionZero::Mcl  => 0x1D | size_to_byte(&Size::Word),
            }
        }
        AstNode::OperationOne {size, instruction, ..} => {
            match instruction {
                InstructionOne::Inc   => 0x11 | size_to_byte(size),
                InstructionOne::Dec   => 0x31 | size_to_byte(size),
                InstructionOne::Not   => 0x33 | size_to_byte(size),
                InstructionOne::Jmp   => 0x08 | size_to_byte(size),
                InstructionOne::Call  => 0x18 | size_to_byte(size),
                InstructionOne::Loop  => 0x28 | size_to_byte(size),
                InstructionOne::Rjmp  => 0x09 | size_to_byte(size),
                InstructionOne::Rcall => 0x19 | size_to_byte(size),
                InstructionOne::Rloop => 0x29 | size_to_byte(size),
                InstructionOne::Push  => 0x0A | size_to_byte(size),
                InstructionOne::Pop   => 0x1A | size_to_byte(size),
                InstructionOne::Int   => 0x2C | size_to_byte(size),
                InstructionOne::Tlb   => 0x2D | size_to_byte(size),
                InstructionOne::Flp   => 0x3D | size_to_byte(size),
            }
        }
        AstNode::OperationTwo {size, instruction, ..} => {
            match instruction {
                InstructionTwo::Add  => 0x01 | size_to_byte(size),
                InstructionTwo::Sub  => 0x21 | size_to_byte(size),
                InstructionTwo::Mul  => 0x02 | size_to_byte(size),
                InstructionTwo::Div  => 0x22 | size_to_byte(size),
                InstructionTwo::Rem  => 0x32 | size_to_byte(size),
                InstructionTwo::And  => 0x03 | size_to_byte(size),
                InstructionTwo::Or   => 0x13 | size_to_byte(size),
                InstructionTwo::Xor  => 0x23 | size_to_byte(size),
                InstructionTwo::Sla  => 0x04 | size_to_byte(size),
                InstructionTwo::Sra  => 0x05 | size_to_byte(size),
                InstructionTwo::Srl  => 0x15 | size_to_byte(size),
                InstructionTwo::Rol  => 0x24 | size_to_byte(size),
                InstructionTwo::Ror  => 0x25 | size_to_byte(size),
                InstructionTwo::Bse  => 0x06 | size_to_byte(size),
                InstructionTwo::Bcl  => 0x16 | size_to_byte(size),
                InstructionTwo::Bts  => 0x26 | size_to_byte(size),
                InstructionTwo::Cmp  => 0x07 | size_to_byte(size),
                InstructionTwo::Mov  => 0x17 | size_to_byte(size),
                InstructionTwo::Movz => 0x27 | size_to_byte(size),
                InstructionTwo::Rta  => 0x39 | size_to_byte(size),
                InstructionTwo::In   => 0x0B | size_to_byte(size),
                InstructionTwo::Out  => 0x1B | size_to_byte(size),
            }
        }
        _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
    }
}

fn condition_source_destination_to_byte(node: &AstNode) -> u8 {
    let source: u8 = match node {
        AstNode::OperationZero {..} => 0x00,
        AstNode::OperationOne {operand, ..} => {
            match operand.as_ref() {
                AstNode::Register(_) => 0x00,
                AstNode::RegisterPointer(_) => 0x01,
                AstNode::Immediate8(_) | AstNode::Immediate16(_) | AstNode::Immediate32(_) | AstNode::LabelOperand {..} => 0x02,
                AstNode::ImmediatePointer(_) | AstNode::LabelOperandPointer {..} => 0x03,
                _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
            }
        }
        AstNode::OperationTwo {rhs, ..} => {
            match rhs.as_ref() {
                AstNode::Register(_) => 0x00,
                AstNode::RegisterPointer(_) => 0x01,
                AstNode::Immediate8(_) | AstNode::Immediate16(_) | AstNode::Immediate32(_) | AstNode::LabelOperand {..} => 0x02,
                AstNode::ImmediatePointer(_) | AstNode::LabelOperandPointer {..} => 0x03,
                _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
            }
        }
        _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
    };
    let destination: u8 = match node {
        AstNode::OperationZero {..} => 0x00,
        AstNode::OperationOne {..} => 0x00,
        AstNode::OperationTwo {lhs, ..} => {
            match lhs.as_ref() {
                AstNode::Register(_) => 0x00,
                AstNode::RegisterPointer(_) => 0x04,
                AstNode::ImmediatePointer(_) | AstNode::LabelOperandPointer {..} => 0x0C,
                _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
            }
        }
        _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
    };
    let condition: u8 = match node {
        AstNode::OperationZero {condition, ..} => {
            match condition {
                Condition::Always => 0x00,
                Condition::Zero => 0x10,
                Condition::NotZero => 0x20,
                Condition::Carry => 0x30,
                Condition::NotCarry => 0x40,
                Condition::GreaterThan => 0x50,
                Condition::LessThanEqualTo => 0x60,
            }
        }
        AstNode::OperationOne {condition, ..} => {
            match condition {
                Condition::Always => 0x00,
                Condition::Zero => 0x10,
                Condition::NotZero => 0x20,
                Condition::Carry => 0x30,
                Condition::NotCarry => 0x40,
                Condition::GreaterThan => 0x50,
                Condition::LessThanEqualTo => 0x60,
            }
        }
        AstNode::OperationTwo {condition, ..} => {
            match condition {
                Condition::Always => 0x00,
                Condition::Zero => 0x10,
                Condition::NotZero => 0x20,
                Condition::Carry => 0x30,
                Condition::NotCarry => 0x40,
                Condition::GreaterThan => 0x50,
                Condition::LessThanEqualTo => 0x60,
            }
        }
        _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
    };
    condition | source | destination
}

fn generate_backpatch_immediate(name: &String, size: &Size, instruction: &AssembledInstruction, is_relative: bool) {
    let index = instruction.borrow().len();
    {
        let mut vec = instruction.borrow_mut();
        let range = match size {
            Size::Byte => 0..1,
            Size::Half => 0..2,
            Size::Word => 0..4,
        };
        for _ in range {
            vec.push(0xAB);
        }
    }
    let mut table = LABEL_TARGETS.lock().unwrap();
    let targets = {
        if let Some(targets) = table.get_mut(name) {
            targets
        } else {
            table.insert(name.clone(), Vec::new());
            table.get_mut(name).unwrap()
        }
    };
    targets.push(BackpatchTarget::new(instruction, index, *size, is_relative));
}

fn node_to_immediate_values(node: &AstNode, instruction: &AssembledInstruction) {
    {
        let mut vec = instruction.borrow_mut();

        match node {
            AstNode::OperationZero {..} => {}

            AstNode::OperationOne {operand, ..} => {
                match *operand.as_ref() {
                    AstNode::Register       (register) => vec.push(register),
                    AstNode::RegisterPointer(register) => vec.push(register),

                    AstNode::Immediate8      (immediate) => vec.push(immediate),
                    AstNode::Immediate16     (immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),
                    AstNode::Immediate32     (immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),
                    AstNode::ImmediatePointer(immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),

                    AstNode::LabelOperand        {ref name, ref size, is_relative} => {
                        std::mem::drop(vec);
                        generate_backpatch_immediate(name, size, instruction, is_relative);
                    }
                    AstNode::LabelOperandPointer {ref name, is_relative} => {
                        std::mem::drop(vec);
                        generate_backpatch_immediate(name, &Size::Word, instruction, is_relative);
                    }

                    _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
                }
            }

            AstNode::OperationTwo {rhs, ..} => {
                match *rhs.as_ref() {
                    AstNode::Register       (register) => vec.push(register),
                    AstNode::RegisterPointer(register) => vec.push(register),

                    AstNode::Immediate8      (immediate) => vec.push(immediate),
                    AstNode::Immediate16     (immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),
                    AstNode::Immediate32     (immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),
                    AstNode::ImmediatePointer(immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),

                    AstNode::LabelOperand        {ref name, ref size, is_relative} => {
                        std::mem::drop(vec);
                        generate_backpatch_immediate(name, size, instruction, is_relative);
                    }
                    AstNode::LabelOperandPointer {ref name, is_relative} => {
                        std::mem::drop(vec);
                        generate_backpatch_immediate(name, &Size::Word, instruction, is_relative);
                    }

                    _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
                }
            }

            _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
        }
    }

    let mut vec = instruction.borrow_mut();

    match node {
        AstNode::OperationZero {..} => {}
        AstNode::OperationOne  {..} => {}

        AstNode::OperationTwo  {lhs, ..} => {
            match *lhs.as_ref() {
                AstNode::Register       (register) => vec.push(register),
                AstNode::RegisterPointer(register) => vec.push(register),

                AstNode::ImmediatePointer(immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),

                AstNode::LabelOperand        {ref name, ref size, is_relative} => {
                    std::mem::drop(vec);
                    generate_backpatch_immediate(name, size, instruction, is_relative);
                }
                AstNode::LabelOperandPointer {ref name, is_relative} => {
                    std::mem::drop(vec);
                    generate_backpatch_immediate(name, &Size::Word, instruction, is_relative);
                }

                _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
            }
        }

        _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", node),
    };
}
