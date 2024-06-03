use crate::{
    instr::{AssembledInstruction, Size},
    POISONED_MUTEX_ERR, RELOC_ADDRESSES,
};

#[derive(Debug, Clone)]
pub struct BackpatchTarget {
    index: usize,
    size: Size,
    is_relative: bool,
    instruction: AssembledInstruction,
}

impl BackpatchTarget {
    pub fn new(
        instruction: &AssembledInstruction,
        index: usize,
        size: Size,
        is_relative: bool,
    ) -> BackpatchTarget {
        Self {
            index,
            is_relative,
            size,
            instruction: instruction.clone(),
        }
    }

    pub fn write(&self, size: Size, address: u32) {
        let instruction = &self.instruction;
        let mut instruction_data = instruction.borrow_mut();

        let address_bytes = if self.is_relative {
            (address as i32 - self.instruction.get_address() as i32).to_le_bytes()
        } else {
            address.to_le_bytes()
        };

        match size {
            Size::Byte => instruction_data[self.index] = address_bytes[0],
            Size::Half => {
                instruction_data[self.index] = address_bytes[0];
                instruction_data[self.index + 1] = address_bytes[1];
            }
            Size::Word => {
                instruction_data[self.index] = address_bytes[0];
                instruction_data[self.index + 1] = address_bytes[1];
                instruction_data[self.index + 2] = address_bytes[2];
                instruction_data[self.index + 3] = address_bytes[3];
            }
        }
    }

    pub fn get_backpatch_location(&self) -> u32 {
        self.instruction.get_address() + self.index as u32
    }
}

pub fn perform_backpatching(targets: &Vec<BackpatchTarget>, address: (u32, bool)) {
    for target in targets {
        target.write(target.size, address.0);

        // if this label isn't const or relative, then add it to the reloc table for FXF
        if !address.1 && !target.is_relative {
            let mut reloc_table = RELOC_ADDRESSES.lock().expect(POISONED_MUTEX_ERR);
            reloc_table.push(target.get_backpatch_location());
        }
    }
}

pub mod immediate {
    use crate::{
        instr::{AssembledInstruction, Size},
        LABEL_TARGETS, POISONED_MUTEX_ERR,
    };

    use super::BackpatchTarget;

    pub fn generate_backpatch(
        name: &String,
        size: Size,
        instruction: &AssembledInstruction,
        is_relative: bool,
    ) -> anyhow::Result<()> {
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
        let mut table = LABEL_TARGETS.lock().expect(POISONED_MUTEX_ERR);
        let targets = {
            if let Some(targets) = table.get_mut(name) {
                targets
            } else {
                table.insert(name.clone(), Vec::new());
                table.get_mut(name).ok_or(anyhow::Error::msg(format!(
                    "could not get mutable reference to target {name}"
                )))?
            }
        };
        targets.push(BackpatchTarget::new(instruction, index, size, is_relative));

        Ok(())
    }
}
