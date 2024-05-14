use crate::{instr::Size, util::remove_underscores};

use super::{AstNode, Rule};

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
            panic!()
        }
    }
}
