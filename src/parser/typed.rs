use crate::instr::Condition;

use super::{data::parse_operand, AstNode, Size, Rule};

pub fn parse_opt(rule: pest::iterators::Pair<Rule>) -> AstNode {
    match rule.as_str() {
        "opton"=>AstNode::Optimize(true),
        "optoff"=>AstNode::Optimize(false),
        _ => panic!("Unknown optimize flag {}", rule.as_str())
    }
}
pub fn parse_origin(pair: pest::iterators::Pair<Rule>) -> AstNode {
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

pub fn parse_size(pair: &pest::iterators::Pair<Rule>) -> Size {
    match pair.as_str() {
        ".8" => Size::Byte,
        ".16" => Size::Half,
        ".32" => Size::Word,
        _ => panic!("Unsupported size: {}", pair.as_str()),
    }
}

pub fn parse_incdec_amount(pair: pest::iterators::Pair<Rule>) -> AstNode {
    match pair.as_str() {
        "1" => AstNode::Immediate8(0),
        "2" => AstNode::Immediate8(1),
        "4" => AstNode::Immediate8(2),
        "8" => AstNode::Immediate8(3),
        _ => panic!("Unsupported increment/decrement: {}", pair.as_str()),
    }
}

pub fn parse_condition(pair: &pest::iterators::Pair<Rule>) -> Condition {
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