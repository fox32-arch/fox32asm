use std::{fs::File, io::Write as _, path::PathBuf, process};

use crate::{
    include::include_text_file,
    instr::AssembledInstruction,
    parser::{self, backpatch::perform_backpatching, AstNode},
    util::format_address_table,
    SizeOrLabelName, FXF_RELOC_PTR, FXF_RELOC_SIZE, LABEL_ADDRESSES, LABEL_TARGETS,
    POISONED_MUTEX_ERR, RELOC_ADDRESSES, SOURCE_PATH,
};

pub mod node;

use node::{assemble_node, optimize_node};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum BinaryType {
    Fxf,
    #[default]
    Flat,
}

pub struct Assembler {
    /// Tuple of the input file contents as a [String], and the canonicalzed
    /// [PathBuf] pointing to it.
    pub input: (String, PathBuf),

    /// Tuple of the output file name as a [String] and the [File] descriptor
    /// for it.
    pub output: (String, File),

    /// The input file, parsed as a collection of AST Nodes.
    pub ast: Vec<AstNode>,

    /// The assembled instructions from the AST Nodes.
    pub instructions: Vec<AssembledInstruction>,
}

impl Assembler {
    pub fn parse_includes(&mut self) -> anyhow::Result<&mut Self> {
        println!("Parsing includes...");

        let mut source_path = SOURCE_PATH.lock().expect(POISONED_MUTEX_ERR);
        source_path.clone_from(&self.input.1);

        for _ in 0..128 {
            let loop_file = self.input.0.clone(); // this is a hack to allow modifying input_file from inside the for loop
            for (line_number, text) in loop_file.lines().enumerate() {
                match text.trim() {
                    s if s.starts_with("#include \"") => {
                        self.input.0 =
                            include_text_file(line_number, text.trim(), self.input.0.clone())
                                .ok_or(anyhow::Error::msg(format!(
                                    "failed to include text file {}",
                                    self.input.1.display()
                                )))?;
                        break;
                    }
                    _ => {}
                };
            }
        }

        Ok(self)
    }

    pub fn parse(&mut self) -> &mut Self {
        println!("Parsing file...");
        self.ast = match parser::parse(&self.input.0) {
            Ok(x) => x,
            Err(x) => {
                println!("{:#?}", x);
                process::exit(1);
            }
        };

        self
    }

    pub fn assemble(&mut self) -> anyhow::Result<&mut Self> {
        let mut current_address: u32 = 0;

        println!("Assembling...");
        let mut optimize = false;
        for node in &self.ast {
            let mut node = node.clone();
            node = optimize_node(node, &mut optimize);
            if let AstNode::LabelDefine { name, .. } = node {
                let mut address_table = LABEL_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
                if address_table.get(&name).is_some() {
                    // this label already exists, print an error and exit
                    println!("Label \"{}\" was defined more than once!", name);
                    process::exit(1);
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
                self.instructions.push(vec![0; difference].into());
            } else if let AstNode::DataFill { value, size } = node {
                let size = match size {
                    SizeOrLabelName::Size(size) => size,
                    SizeOrLabelName::Label(name) => {
                        let address_table = LABEL_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
                        let label = address_table
                            .get(&name)
                            .expect(&format!("Label not found: {}", name));
                        label.0
                    }
                };
                current_address += size;
                self.instructions.push(vec![value; size as usize].into());
            } else if let AstNode::IncludedBinary(binary_vec) = node {
                current_address += binary_vec.len() as u32;
                self.instructions.push(binary_vec.clone().into());
            } else if let AstNode::Optimize(_) = node {
            } else {
                let instruction = assemble_node(node.clone())?;
                instruction.set_address(current_address);
                current_address += instruction.borrow().len() as u32;
                self.instructions.push(instruction);
            }
        }

        Ok(self)
    }

    pub fn batchpatch_labels(&mut self) -> &mut Self {
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
                    .unwrap_or_else(|| panic!("Label not found: {}", name)),
            );
        }

        std::mem::drop(table);
        std::mem::drop(address_table);
        self
    }

    pub fn build_binary(&mut self, binary_type: BinaryType) -> anyhow::Result<()> {
        let is_fxf = binary_type == BinaryType::Fxf;
        let mut binary = Vec::new();

        // if we're generating a FXF binary, write out the header first
        if is_fxf {
            // magic bytes and version
            binary.push(b'F');
            binary.push(b'X');
            binary.push(b'F');
            binary.push(0);

            let mut code_size = 0;
            for instruction in &self.instructions {
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

        for instruction in &self.instructions {
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

        self.output
            .1
            .write_all(&binary)
            .map_err(anyhow::Error::from)
    }
}
