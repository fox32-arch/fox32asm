use pest::{error::Error, Parser as _};
use pest_derive::Parser;

use crate::{
    include::include_binary_file,
    instr::{
        parse_instruction_incdec, parse_instruction_one, parse_instruction_two,
        parse_instruction_zero, Condition, LabelKind, OperationIncDec, OperationOne, OperationTwo,
        OperationZero, Size,
    },
    SizeOrLabelName, CURRENT_CONDITION, CURRENT_SIZE, POISONED_MUTEX_ERR,
};

use self::{
    data::{parse_constant, parse_data, parse_operand},
    label::parse_label,
    typed::{parse_condition, parse_incdec_amount, parse_opt, parse_origin, parse_size},
};

pub mod backpatch;
pub mod data;
pub mod immediate;
pub mod label;
pub mod typed;

#[derive(Parser)]
#[grammar = "fox32.pest"]
pub struct Fox32Parser;

#[derive(PartialEq, Debug, Clone)]
pub enum AstNode {
    OperationZero(OperationZero),
    OperationOne(OperationOne),
    OperationIncDec(OperationIncDec),
    OperationTwo(OperationTwo),

    Immediate8(u8),
    Immediate16(u16),
    Immediate32(u32),
    Register(u8),
    ImmediatePointer(u32),
    RegisterPointer(u8),
    RegisterPointerOffset(u8, u8),
    RegisterPointerBackpatchOffset(u8, String),

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
    DataStrZero(String),
    DataFill {
        value: u8,
        size: SizeOrLabelName,
    },

    IncludedBinary(Vec<u8>),

    Origin(u32),
    OriginPadded(u32),
    Optimize(bool),
}
fn parse_instruction(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("parse_instruction: {:#?}", pair); // debug
    let mut size = Size::Word;
    let condition = *CURRENT_CONDITION.lock().expect(POISONED_MUTEX_ERR);
    match pair.as_rule() {
        Rule::instruction_conditional => {
            let mut inner_pair = pair.into_inner();
            let instruction_conditional_pair = inner_pair.next().unwrap();
            match instruction_conditional_pair.as_rule() {
                Rule::instruction_zero => {
                    if let Some(inner) = inner_pair.peek() {
                        if inner.as_rule() == Rule::size {
                            size = parse_size(&inner_pair.next().unwrap());
                        }
                    }
                    *CURRENT_SIZE.lock().expect(POISONED_MUTEX_ERR) = size;
                    parse_instruction_zero(instruction_conditional_pair, size, condition)
                }
                Rule::instruction_one => {
                    if inner_pair.peek().unwrap().as_rule() == Rule::size {
                        size = parse_size(&inner_pair.next().unwrap());
                    }
                    *CURRENT_SIZE.lock().expect(POISONED_MUTEX_ERR) = size;
                    let operand = inner_pair.next().unwrap();
                    let operand_ast = build_ast_from_expression(operand);
                    parse_instruction_one(
                        instruction_conditional_pair,
                        operand_ast,
                        size,
                        condition,
                    )
                }
                Rule::instruction_incdec => {
                    if inner_pair.peek().unwrap().as_rule() == Rule::size {
                        size = parse_size(&inner_pair.next().unwrap());
                    }
                    *CURRENT_SIZE.lock().expect(POISONED_MUTEX_ERR) = size;
                    let lhs = inner_pair.next().unwrap();
                    let lhs_ast = build_ast_from_expression(lhs);
                    let rhs_ast = if inner_pair.peek().is_some() {
                        let rhs = inner_pair.next().unwrap();
                        parse_incdec_amount(rhs)
                    } else {
                        AstNode::Immediate8(0)
                    };
                    parse_instruction_incdec(
                        instruction_conditional_pair,
                        lhs_ast,
                        rhs_ast,
                        size,
                        condition,
                    )
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
                    parse_instruction_two(
                        instruction_conditional_pair,
                        lhs_ast,
                        rhs_ast,
                        size,
                        condition,
                    )
                }
                _ => todo!(),
            }
        }
        _ => panic!("Unsupported instruction type: {:#?}", pair.as_rule()),
    }
}

fn build_ast_from_expression(pair: pest::iterators::Pair<Rule>) -> AstNode {
    //println!("{:#?}\n\n", pair); // debug
    let pair_rule = pair.as_rule();
    let mut inner_pair = pair.into_inner();
    *CURRENT_CONDITION.lock().expect(POISONED_MUTEX_ERR) = Condition::Always;
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
        Rule::opt => parse_opt(inner_pair.next().unwrap()),
        Rule::origin => parse_origin(inner_pair.next().unwrap()),
        Rule::include_bin => include_binary_file(inner_pair.next().unwrap(), false),
        Rule::include_bin_optional => include_binary_file(inner_pair.next().unwrap(), true),
        _ => todo!("{:#?}", pair_rule),
    }
}

pub fn parse(source: &str) -> Result<Vec<AstNode>, Box<Error<Rule>>> {
    let mut ast = vec![];
    let pairs = Fox32Parser::parse(Rule::assembly, source)?;

    for pair in pairs.peek().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::EOI => break,
            _ => ast.push(build_ast_from_expression(pair)),
        }
    }

    Ok(ast)
}
