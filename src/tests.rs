use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::PathBuf,
};

use crate::{
    instr::{Condition, Size},
    parser::backpatch::BackpatchTarget,
    Assembler, BinaryType, CURRENT_CONDITION, CURRENT_SIZE, LABEL_ADDRESSES, LABEL_TARGETS,
    RELOC_ADDRESSES, SOURCE_PATH,
};

macro_rules! reset_statics {
    ($($static:expr => $type:ty,)*) => {
        $(*$static.lock().unwrap() = <$type>::default();)*
    };
}

macro_rules! create_tests {
    ($($name:ident => $path:literal,)*) => {
        $(
            #[test]
            fn $name() -> anyhow::Result<()> {
                let input = {
                    let input_path_string = concat!($path, ".asm");
                    (
                        fs::read_to_string(input_path_string)?,
                        {
                            let mut inner = fs::canonicalize(input_path_string)?;
                            inner.pop();
                            inner
                        }
                    )
                };
                let output = {
                    let output_path_str = concat!($path, ".fxf").to_string();
                    (
                        output_path_str.clone(),
                        fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .create(true)
                            .open(output_path_str)?
                    )
                };

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
                    .backpatch_labels()
                    .build_binary(BinaryType::Fxf)?;

                reset_statics! {
                    SOURCE_PATH => PathBuf,
                    CURRENT_SIZE => Size,
                    CURRENT_CONDITION => Condition,
                    LABEL_TARGETS => BTreeMap<String, Vec<BackpatchTarget>>,
                    LABEL_ADDRESSES => HashMap<String, (u32, bool)>,
                    RELOC_ADDRESSES => Vec<u32>,
                };

                Ok(())
            }
        )*
    };
}

create_tests! {
    cputest => "asm-test/cputest/cputest-bin",
    tcc => "asm-test/boot/tcc",
    allocate => "asm-test/demos/allocate/allocate",
    hello_world => "asm-test/demos/hello_world/hello",
    multitasking => "asm-test/demos/multitasking/multitsk",
    robotfindskitten => "asm-test/demos/robotfindskitten/rfk",
    negative_imm => "asm-test-local/negative-imm",
}
