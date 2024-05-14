use crate::{
    instr::{AssembledInstruction, InstructionIncDec, InstructionTwo, OperationIncDec, Size},
    parser::{backpatch::immediate, immediate::node_to_immediate_values, AstNode},
    util::conversion::{condition_source_destination_to_byte, instruction_to_byte},
};

pub fn assemble_node(node: AstNode) -> anyhow::Result<AssembledInstruction> {
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

pub fn node_value(node: &AstNode) -> Option<u32> {
    match *node {
        AstNode::Immediate16(n) => Some(n as u32),
        AstNode::Immediate32(n) => Some(n),
        AstNode::Immediate8(n) => Some(n as u32),
        _ => None,
    }
}
pub fn optimize_node(node: AstNode, enabled: &mut bool) -> AstNode {
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
