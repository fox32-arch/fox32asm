use lazy_static::lazy_static;
use std::{
    collections::{BTreeMap, HashMap},
    env,
    fmt::Debug,
    fs,
    path::PathBuf,
    process,
    sync::Mutex,
};

pub(crate) mod assembler;
pub(crate) mod include;
pub(crate) mod instr;
pub(crate) mod parser;
pub(crate) mod util;

#[cfg(test)]
mod tests;

use crate::{
    assembler::{Assembler, BinaryType},
    instr::{Condition, Size},
    parser::backpatch::BackpatchTarget,
};

// this is kinda dumb, but oh well !!
lazy_static! {
    static ref SOURCE_PATH: Mutex<PathBuf> = Mutex::new(PathBuf::new());
    static ref CURRENT_SIZE: Mutex<Size> = Mutex::new(Size::Word);
    static ref CURRENT_CONDITION: Mutex<Condition> = Mutex::new(Condition::Always);
    static ref LABEL_TARGETS: Mutex<BTreeMap<String, Vec<BackpatchTarget>>> =
        Mutex::new(BTreeMap::new());
    static ref LABEL_ADDRESSES: Mutex<HashMap<String, (u32, bool)>> = Mutex::new(HashMap::new());
    static ref RELOC_ADDRESSES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
}

//const FXF_CODE_SIZE:   usize = 0x00000004;
//const FXF_CODE_PTR:    usize = 0x00000008;
const FXF_RELOC_SIZE: usize = 0x0000000C;
const FXF_RELOC_PTR: usize = 0x00000010;
const LBR_JUMP_SIZE: usize = 0x00000014;
const LBR_JUMP_PTR: usize = 0x00000018;

// Used by data.fill to store either a known size or the name of a constant
// that defines the size
#[derive(PartialEq, Debug, Clone)]
enum SizeOrLabelName {
    Size(u32),
    Label(String),
}

pub const POISONED_MUTEX_ERR: &str = "failed to lock mutex; possibly poisoined";

fn main() -> anyhow::Result<()> {
    let version_string = format!(
        "fox32asm {} ({})",
        env!("VERGEN_BUILD_SEMVER"),
        env!("VERGEN_GIT_SHA_SHORT")
    );
    println!("{}", version_string);

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <input> <output>", args[0]);
        process::exit(1);
    }

    let input_file_name = &args[1];
    let output_file_name = &args[2];

    let is_fxf = output_file_name.ends_with(".fxf");
    let is_lbr = output_file_name.ends_with(".lbr");
    if is_fxf {
        println!("Generating FXF binary");
    } else if is_lbr {
        println!("Generating LBR library");
    } else {
        println!("Generating raw binary");
    }

    let input = (
        fs::read_to_string(input_file_name).expect("cannot read file"),
        {
            let mut inner = fs::canonicalize(input_file_name)?;
            inner.pop();
            inner
        },
    );

    let output = (
        output_file_name.to_string(),
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(output_file_name)?,
    );

    let mut assembler = Assembler {
        input,
        output,
        ast: Vec::new(),
        instructions: Vec::new(),
    };

    assembler
        .parse_includes()?
        .parse()?
        .assemble()?
        .batchpatch_labels()
        .build_binary(if is_fxf {
            BinaryType::Fxf
        } else if is_lbr {
            BinaryType::Lbr
        } else {
            BinaryType::Flat
        })
}
