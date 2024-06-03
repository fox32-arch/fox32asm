use std::{
    cell::{Cell, RefCell},
    ops::Deref,
    rc::Rc,
};

use crate::{
    assembler::node::node_value,
    parser::{AstNode, Rule},
};

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum InstructionZero {
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
pub enum InstructionOne {
    // one operand
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
pub enum InstructionIncDec {
    // one or two operands
    Inc,
    Dec,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum InstructionTwo {
    // two operands
    Add,
    Sub,
    Mul,
    Imul,
    Div,
    Idiv,
    Rem,
    Irem,
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

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub enum Size {
    Byte,
    Half,
    #[default]
    Word,
}

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub enum Condition {
    #[default]
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
pub enum LabelKind {
    Internal,
    External,
    Global,
}

#[derive(PartialEq, Debug, Clone)]
pub struct OperationZero {
    pub size: Size,
    pub condition: Condition,
    pub instruction: InstructionZero,
}
#[derive(PartialEq, Debug, Clone)]
pub struct OperationOne {
    pub size: Size,
    pub condition: Condition,
    pub instruction: InstructionOne,
    pub operand: Box<AstNode>,
}
#[derive(PartialEq, Debug, Clone)]
pub struct OperationIncDec {
    pub size: Size,
    pub condition: Condition,
    pub instruction: InstructionIncDec,
    pub lhs: Box<AstNode>,
    pub rhs: Box<AstNode>,
}
#[derive(PartialEq, Debug, Clone)]
pub struct OperationTwo {
    pub size: Size,
    pub condition: Condition,
    pub instruction: InstructionTwo,
    pub lhs: Box<AstNode>,
    pub rhs: Box<AstNode>,
}

#[derive(Debug, Clone, Default)]
pub struct AssembledInstruction {
    value: Rc<RefCell<Vec<u8>>>,
    address: Rc<Cell<u32>>,
}

impl AssembledInstruction {
    pub fn new() -> Self {
        Self {
            value: Rc::default(),
            address: Rc::default(),
        }
    }

    pub fn get_address(&self) -> u32 {
        self.address.get()
    }
    pub fn set_address(&self, address: u32) {
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

pub fn parse_instruction_zero(
    pair: pest::iterators::Pair<Rule>,
    size: Size,
    condition: Condition,
) -> AstNode {
    AstNode::OperationZero(OperationZero {
        size,
        condition,
        instruction: match pair.as_str() {
            "nop" => InstructionZero::Nop,
            "halt" => InstructionZero::Halt,
            "brk" => InstructionZero::Brk,
            "ret" => InstructionZero::Ret,
            "reti" => InstructionZero::Reti,
            "ise" => InstructionZero::Ise,
            "icl" => InstructionZero::Icl,
            "mse" => InstructionZero::Mse,
            "mcl" => InstructionZero::Mcl,
            _ => panic!(
                "Unsupported conditional instruction (zero): {}",
                pair.as_str()
            ),
        },
    })
}

pub fn parse_instruction_one(
    pair: pest::iterators::Pair<Rule>,
    mut operand: AstNode,
    size: Size,
    condition: Condition,
) -> AstNode {
    AstNode::OperationOne(OperationOne {
        size,
        condition,
        instruction: match pair.as_str() {
            "not" => InstructionOne::Not,
            "jmp" => InstructionOne::Jmp,
            "call" => InstructionOne::Call,
            "loop" => InstructionOne::Loop,
            "rjmp" => {
                match &mut operand {
                    &mut AstNode::LabelOperand {
                        ref mut is_relative,
                        ..
                    }
                    | &mut AstNode::LabelOperandPointer {
                        ref mut is_relative,
                        ..
                    } => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionOne::Rjmp
            }
            "rcall" => {
                match &mut operand {
                    &mut AstNode::LabelOperand {
                        ref mut is_relative,
                        ..
                    }
                    | &mut AstNode::LabelOperandPointer {
                        ref mut is_relative,
                        ..
                    } => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionOne::Rcall
            }
            "rloop" => {
                match &mut operand {
                    &mut AstNode::LabelOperand {
                        ref mut is_relative,
                        ..
                    }
                    | &mut AstNode::LabelOperandPointer {
                        ref mut is_relative,
                        ..
                    } => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionOne::Rloop
            }
            "push" => InstructionOne::Push,
            "pop" => InstructionOne::Pop,
            "int" => InstructionOne::Int,
            "tlb" => InstructionOne::Tlb,
            "flp" => InstructionOne::Flp,
            _ => panic!(
                "Unsupported conditional instruction (one): {}",
                pair.as_str()
            ),
        },
        operand: Box::new(operand),
    })
}

pub fn parse_instruction_incdec(
    pair: pest::iterators::Pair<Rule>,
    lhs: AstNode,
    rhs: AstNode,
    size: Size,
    condition: Condition,
) -> AstNode {
    AstNode::OperationIncDec(OperationIncDec {
        size,
        condition,
        instruction: match pair.as_str() {
            "inc" => InstructionIncDec::Inc,
            "dec" => InstructionIncDec::Dec,
            _ => panic!(
                "Unsupported conditional instruction (two): {}",
                pair.as_str()
            ),
        },
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })
}

pub fn parse_instruction_two(
    pair: pest::iterators::Pair<Rule>,
    mut lhs: AstNode,
    mut rhs: AstNode,
    size: Size,
    condition: Condition,
) -> AstNode {
    match pair.as_str() {
        "sla" | "sra" | "srl" | "rol" | "ror" | "bse" | "bcl" | "bts" => {
            if let Some(value) = node_value(&rhs) {
                rhs = AstNode::Immediate8(value as u8);
            }
        }
        _ => (),
    }
    AstNode::OperationTwo(OperationTwo {
        size,
        condition,
        instruction: match pair.as_str() {
            "add" => InstructionTwo::Add,
            "sub" => InstructionTwo::Sub,
            "mul" => InstructionTwo::Mul,
            "imul" => InstructionTwo::Imul,
            "div" => InstructionTwo::Div,
            "idiv" => InstructionTwo::Idiv,
            "rem" => InstructionTwo::Rem,
            "irem" => InstructionTwo::Irem,
            "and" => InstructionTwo::And,
            "or" => InstructionTwo::Or,
            "xor" => InstructionTwo::Xor,
            "sla" => InstructionTwo::Sla,
            "sra" => InstructionTwo::Sra,
            "srl" => InstructionTwo::Srl,
            "rol" => InstructionTwo::Rol,
            "ror" => InstructionTwo::Ror,
            "bse" => InstructionTwo::Bse,
            "bcl" => InstructionTwo::Bcl,
            "bts" => InstructionTwo::Bts,
            "cmp" => InstructionTwo::Cmp,
            "mov" => InstructionTwo::Mov,
            "movz" => InstructionTwo::Movz,
            "rta" => {
                match &mut lhs {
                    &mut AstNode::LabelOperand {
                        ref mut is_relative,
                        ..
                    }
                    | &mut AstNode::LabelOperandPointer {
                        ref mut is_relative,
                        ..
                    } => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                match &mut rhs {
                    &mut AstNode::LabelOperand {
                        ref mut is_relative,
                        ..
                    }
                    | &mut AstNode::LabelOperandPointer {
                        ref mut is_relative,
                        ..
                    } => {
                        *is_relative = true;
                    }
                    _ => {}
                }
                InstructionTwo::Rta
            }
            "in" => InstructionTwo::In,
            "out" => InstructionTwo::Out,
            _ => panic!(
                "Unsupported conditional instruction (two): {}",
                pair.as_str()
            ),
        },
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })
}
