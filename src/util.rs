use std::collections::HashMap;

use crate::instr::Size;

pub fn format_address_table(m: &HashMap<String, (u32, bool)>) -> String {
    let mut v: Vec<(&String, &u32)> = Vec::new();
    for i in m.into_iter() {
        v.push((i.0, &i.1.0));
    }
    v.sort_by(|(_, v1), (_, v2)| u32::cmp(v1, v2));
    v.iter().map(|(k, v)| format!("{:#010X?} :: {}", v, k)).collect::<Vec<String>>().join("\n")
}

pub fn remove_underscores(input: &str) -> String {
    String::from_iter(input.chars().filter(|c| *c != '_'))
}

pub fn size_to_byte(size: Size) -> u8 {
    match size {
        Size::Byte => 0b00000000,
        Size::Half => 0b01000000,
        Size::Word => 0b10000000,
    }
}