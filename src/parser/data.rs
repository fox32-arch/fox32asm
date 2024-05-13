use crate::{instr::Size, SizeOrLabelName, CURRENT_SIZE};

use super::{immediate::{immediate_to_astnode, parse_immediate}, AstNode, Rule};

fn parse_register(pair: pest::iterators::Pair<Rule>) -> u8 {
    let register_num_pair = pair.into_inner().next().unwrap();
    let register_num = if register_num_pair.as_str() == "sp" { 32 }
    else if register_num_pair.as_str() == "esp" { 33 }
    else if register_num_pair.as_str() == "fp" { 34 }
    else { register_num_pair.as_str().parse::<u8>().unwrap() };
    if register_num > 34 { panic!("register number out of range"); }
    register_num
}

pub fn parse_operand(mut pair: pest::iterators::Pair<Rule>, is_pointer: bool) -> AstNode {
    //println!("parse_operand: {:#?}", pair); // debug
    // dbg!(&pair);
    let size = *CURRENT_SIZE.lock().unwrap();
    let pointer_offset = 
    if is_pointer {
        // skip past the operand_value_ptr pair and look at its operand_value rule
        let mut pairs = pair.into_inner();
        pair = pairs.next().unwrap();
        pairs.next()
        // pair = pair.into_inner().next().unwrap();
    }else {
        None
    };
    match pair.as_rule() {
        Rule::operand_value => {
            let mut inner_pair = pair.into_inner();
            let operand_value_pair = inner_pair.next().unwrap();
            match operand_value_pair.as_rule() {
                Rule::immediate_bin|
                Rule::immediate_char|
                Rule::immediate_dec|
                Rule::immediate_hex => {
                    immediate_to_astnode(parse_immediate(operand_value_pair), size, is_pointer)
                }
                Rule::register => {
                    let register_num = parse_register(operand_value_pair);
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
        Rule::register => {
            let register_num = parse_register(pair);
            let offset = if let Some(offset_pair) = pointer_offset {
                parse_immediate(offset_pair.into_inner().next().unwrap())
            } else {
                0
            };
            if offset == 0 {
                AstNode::RegisterPointer(register_num)
            } else {
                AstNode::RegisterPointerOffset(register_num, offset as u8)
            }
        }
        _ => panic!(),
    }
}

pub fn parse_constant(pairs: pest::iterators::Pairs<Rule>) -> AstNode {
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

pub fn parse_data(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("{:#?}", pair);
    *CURRENT_SIZE.lock().unwrap() = Size::Word;
    match pair.as_rule() {
        Rule::data_byte => {
            match parse_operand(pair.into_inner().next().unwrap(), false) {
                AstNode::Immediate32(half) => AstNode::DataByte(half as u8),
                AstNode::LabelOperand {name, size: _, is_relative} =>
                    AstNode::LabelOperand {name, size: Size::Byte, is_relative},
                _ => unreachable!(),
            }
        },
        Rule::data_half => {
            match parse_operand(pair.into_inner().next().unwrap(), false) {
                AstNode::Immediate32(half) => AstNode::DataHalf(half as u16),
                AstNode::LabelOperand {name, size: _, is_relative} =>
                    AstNode::LabelOperand {name, size: Size::Half, is_relative},
                _ => unreachable!(),
            }
        },
        Rule::data_word => {
            match parse_operand(pair.into_inner().next().unwrap(), false) {
                AstNode::Immediate32(word) => AstNode::DataWord(word),
                AstNode::LabelOperand {name, size: _, is_relative} =>
                    AstNode::LabelOperand {name, size: Size::Word, is_relative},
                _ => unreachable!(),
            }
        },
        Rule::data_str => {
            let string = pair.into_inner().next().unwrap().into_inner().next().unwrap().as_str();
            AstNode::DataStr(string.to_string())
        },
        Rule::data_strz => {
            let string = pair.into_inner().next().unwrap().into_inner().next().unwrap().as_str();
            AstNode::DataStrZero(string.to_string())
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
                    SizeOrLabelName::Size(word)
                } else if let AstNode::LabelOperand {name, ..} = ast {
                    SizeOrLabelName::Label(name)
                } else {
                    dbg!(ast);
                    unreachable!()
                }
            };
            AstNode::DataFill {value, size}
        },
        _ => panic!("Unsupported data: {}", pair.as_str()),
    }
}
