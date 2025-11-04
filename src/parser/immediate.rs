use crate::{
    instr::{AssembledInstruction, OperationIncDec, OperationOne, OperationTwo, Size},
    util::remove_underscores,
};

use super::{backpatch::immediate, AstNode, Rule};

pub fn immediate_to_astnode(immediate: u32, size: Size, is_pointer: bool) -> AstNode {
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

pub fn operand_to_immediate_value(
    instruction: &AssembledInstruction,
    node: &AstNode,
    pointer_offset: bool,
) -> anyhow::Result<()> {
    let mut vec = instruction.borrow_mut();
    match *node {
        AstNode::Register(register) => vec.push(register),
        AstNode::RegisterPointer(register) => {
            vec.push(register);
            if pointer_offset {
                vec.push(0);
            }
        }
        AstNode::RegisterPointerOffset(register, offset) => {
            vec.push(register);
            if pointer_offset {
                vec.push(offset);
            }
        }
        AstNode::RegisterPointerBackpatchOffset(register, ref name) => {
            vec.push(register);
            if pointer_offset {
                std::mem::drop(vec);
                immediate::generate_backpatch(name, Size::Byte, instruction, false)?;
            }
        }

        AstNode::Immediate8(immediate) => vec.push(immediate),
        AstNode::Immediate16(immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),
        AstNode::Immediate32(immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),
        AstNode::ImmediatePointer(immediate) => vec.extend_from_slice(&immediate.to_le_bytes()),

        AstNode::LabelOperand {
            ref name,
            size,
            is_relative,
        } => {
            std::mem::drop(vec);
            immediate::generate_backpatch(name, size, instruction, is_relative)?;
        }
        AstNode::LabelOperandPointer {
            ref name,
            is_relative,
        } => {
            std::mem::drop(vec);
            immediate::generate_backpatch(name, Size::Word, instruction, is_relative)?;
        }

        _ => panic!(
            "Attempting to parse a non-instruction AST node as an instruction: {:#?}",
            node
        ),
    }

    Ok(())
}

pub fn node_to_immediate_values(
    node: &AstNode,
    instruction: &AssembledInstruction,
    pointer_offset: bool,
) -> anyhow::Result<()> {
    {
        match node {
            AstNode::OperationZero { .. } => {}

            AstNode::OperationOne(OperationOne { operand, .. }) => {
                operand_to_immediate_value(instruction, operand.as_ref(), pointer_offset)?
            }

            AstNode::OperationIncDec(OperationIncDec { lhs, .. }) => {
                operand_to_immediate_value(instruction, lhs.as_ref(), pointer_offset)?
            }

            AstNode::OperationTwo(OperationTwo { rhs, .. }) => {
                operand_to_immediate_value(instruction, rhs.as_ref(), pointer_offset)?
            }

            _ => panic!(
                "Attempting to parse a non-instruction AST node as an instruction: {:#?}",
                node
            ),
        }
    }

    match node {
        AstNode::OperationZero { .. } => {}
        AstNode::OperationOne { .. } => {}
        AstNode::OperationIncDec { .. } => {}

        AstNode::OperationTwo(OperationTwo { lhs, .. }) => {
            operand_to_immediate_value(instruction, lhs.as_ref(), pointer_offset)?
        }

        _ => panic!(
            "Attempting to parse a non-instruction AST node as an instruction: {:#?}",
            node
        ),
    };

    Ok(())
}

pub fn parse_immediate(pair: pest::iterators::Pair<Rule>) -> u32 {
    match pair.as_rule() {
        Rule::immediate_bin => {
            let body_bin_str = pair.into_inner().next().unwrap().as_str();
            u32::from_str_radix(&remove_underscores(body_bin_str), 2).unwrap()
        }
        Rule::immediate_hex => {
            let body_hex_str = pair.into_inner().next().unwrap().as_str();
            u32::from_str_radix(&remove_underscores(body_hex_str), 16).unwrap()
        }
        Rule::immediate_dec => {
            let dec_str = pair.as_span().as_str();
            remove_underscores(dec_str)
                .parse::<u32>()
                .expect("could not parse integer as u32")
        }
        Rule::immediate_char => {
            let body_char_str = pair.into_inner().next().unwrap().as_str();
            body_char_str.chars().next().unwrap() as u8 as u32
        }
        _ => {
            panic!("Invalid immediate")
        }
    }
}
