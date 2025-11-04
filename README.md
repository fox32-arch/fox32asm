# fox32asm

**fox32asm** is a work-in-progress assembler for **fox32**.

## Getting Started

Stable releases are available on the
[Releases page](https://github.com/fox32-arch/fox32asm/releases).

Prebuilt binaries of the latest commit are also available on the
[GitHub Actions page](https://github.com/fox32-arch/fox32asm/actions).

To build, run `cargo build --release` or `cargo install --path .`.
When building fox32rom or fox32os, it will look for `fox32asm` on the $PATH or at `../fox32asm/target/release/fox32asm`.

### Usage

**fox32asm** expects arguments in the following order: `fox32asm <input> <output>`

The type of binary generated depends on the file extension of `<output>`. The following extensions are recognized:
- `.fxf`: Relocatable fox32os application binary
- `.lbr`: Relocatable fox32os runtime library

Any other extension will result in a flat binary. `.bin` is the convention for flat binaries.

## License
This project is licensed under the [MIT license](LICENSE).
