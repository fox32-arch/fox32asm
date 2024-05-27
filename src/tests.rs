use std::fs;

use crate::{Assembler, BinaryType};

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
                    .parse()
                    .assemble()?
                    .batchpatch_labels()
                    .build_binary(BinaryType::Fxf)
            }
        )*
    };
}

create_tests! {
    cputest => "asm-test/cputest/cputest-bin",
    tcc => "asm-test/boot/tcc",
}
