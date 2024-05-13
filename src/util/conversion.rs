use crate::{
    instr::{
        Condition, InstructionIncDec, InstructionOne, InstructionTwo, InstructionZero,
        OperationIncDec, OperationOne, OperationTwo, OperationZero, Size,
    },
    parser::AstNode,
};

macro_rules! map_instr_opcode {
    ($node:expr,$($op_type:ident:{$instr_type:ident,$($instr:ident => $opcode:expr,)*},)*) => {
        match *$node {
            $(AstNode::$op_type($op_type{size, instruction, ..}) => {
                match instruction {
                    $($instr_type::$instr => $opcode | size_to_byte(size),)*
                }
            })*,
            _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", $node),
        }
    }
}

pub fn instruction_to_byte(node: &AstNode) -> u8 {
    map_instr_opcode!(
        node,

        OperationZero: {
            InstructionZero,
            Nop  => 0x00,
            Halt => 0x10,
            Brk  => 0x20,
            Ret  => 0x2A,
            Reti => 0x3A,
            Ise  => 0x0C,
            Icl  => 0x1C,
            Mse  => 0x0D,
            Mcl  => 0x1D,
        },

        OperationOne: {
            InstructionOne,
            Not   => 0x33,
            Jmp   => 0x08,
            Call  => 0x18,
            Loop  => 0x28,
            Rjmp  => 0x09,
            Rcall => 0x19,
            Rloop => 0x29,
            Push  => 0x0A,
            Pop   => 0x1A,
            Int   => 0x2C,
            Tlb   => 0x2D,
            Flp   => 0x3D,
        },

        OperationIncDec: {
            InstructionIncDec,
            Inc => 0x11,
            Dec => 0x31,
        },

        OperationTwo: {
            InstructionTwo,
            Add  => 0x01,
            Sub  => 0x21,
            Mul  => 0x02,
            Imul => 0x14,
            Div  => 0x22,
            Idiv => 0x34,
            Rem  => 0x32,
            Irem => 0x35,
            And  => 0x03,
            Or   => 0x13,
            Xor  => 0x23,
            Sla  => 0x04,
            Sra  => 0x05,
            Srl  => 0x15,
            Rol  => 0x24,
            Ror  => 0x25,
            Bse  => 0x06,
            Bcl  => 0x16,
            Bts  => 0x26,
            Cmp  => 0x07,
            Mov  => 0x17,
            Movz => 0x27,
            Rta  => 0x39,
            In   => 0x0B,
            Out  => 0x1B,
        },
    )
}

pub fn size_to_byte(size: Size) -> u8 {
    match size {
        Size::Byte => 0b00000000,
        Size::Half => 0b01000000,
        Size::Word => 0b10000000,
    }
}

macro_rules! map_src_byte {
    ($node:expr,$($op_type_zero:ident:$op_zero_byte:expr)*,[$op_type_1:ident=$field_1:ident,$op_type_2:ident=$field_2:ident,$op_type_3:ident=$field_3:ident]:{$($ast_node_type:pat => $ast_node_byte:expr,)*}) => {
        match $node {
            $(AstNode::$op_type_zero(_) => $op_zero_byte,)*
            AstNode::$op_type_1($op_type_1{$field_1, ..}) => {
                use AstNode::*;
                map_src_byte!($node, $field_1, $($ast_node_type => $ast_node_byte)*)
            },
            AstNode::$op_type_2($op_type_2{$field_2, ..}) => {
                use AstNode::*;
                map_src_byte!($node, $field_2, $($ast_node_type => $ast_node_byte)*)
            },
            AstNode::$op_type_3($op_type_3{$field_3, ..}) => {
                use AstNode::*;
                map_src_byte!($node, $field_3, $($ast_node_type => $ast_node_byte)*)
            },
            _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", $node),
        }
    };

    ($node:expr,$field:expr,$($ast_node_type:pat => $ast_node_byte:expr)*) => {
        match $field.as_ref() {
            $($ast_node_type => $ast_node_byte,)*
            _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", $node),
        }
    };
}

macro_rules! map_condition_byte {
    ($node:expr,[$($op:ident$(,)?)*]) => {
        match $node {
            $(AstNode::$op($op{condition, ..}) => condition_to_bits(condition),)*
            _ => panic!("Attempting to parse a non-instruction AST node as an instruction: {:#?}", $node),
        }
    };
}

pub fn condition_source_destination_to_byte(node: &AstNode) -> u8 {
    let source: u8 = map_src_byte!(
        node,
        OperationZero: 0x00,
        [
            OperationOne = operand,
            OperationIncDec = lhs,
            OperationTwo = rhs
        ]: {
            Register(_) => 0x00,
            RegisterPointer(_) => 0x01,
            RegisterPointerOffset{..} => 0x81,
            Immediate8(_) | Immediate16(_) | Immediate32(_) | LabelOperand{..} => 0x02,
            ImmediatePointer(_) | LabelOperandPointer{..} => 0x03,
        }
    );

    let destination: u8 = match node {
        AstNode::OperationZero(_) => 0x00,
        AstNode::OperationOne(_) => 0x00,
        AstNode::OperationIncDec(OperationIncDec { rhs, .. }) => match rhs.as_ref() {
            AstNode::Immediate8(n) => *n << 2,
            _ => panic!(""),
        },
        AstNode::OperationTwo(OperationTwo { lhs, .. }) => match lhs.as_ref() {
            AstNode::Register(_) => 0x00,
            AstNode::RegisterPointer(_) => 0x04,
            AstNode::RegisterPointerOffset(_, _) => 0x84,
            AstNode::Immediate8(_)
            | AstNode::Immediate16(_)
            | AstNode::Immediate32(_)
            | AstNode::LabelOperand { .. } => 0x08,
            AstNode::ImmediatePointer(_) | AstNode::LabelOperandPointer { .. } => 0x0C,
            _ => panic!(
                "Attempting to parse a non-instruction AST node as an instruction: {:#?}",
                node
            ),
        },
        _ => panic!(
            "Attempting to parse a non-instruction AST node as an instruction: {:#?}",
            node
        ),
    };

    let condition: u8 = map_condition_byte!(
        node,
        [OperationZero, OperationOne, OperationIncDec, OperationTwo]
    );

    condition | source | destination
}

pub fn condition_to_bits(condition: &Condition) -> u8 {
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
