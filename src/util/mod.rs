use std::collections::HashMap;

pub mod conversion;

pub fn format_address_table(m: &HashMap<String, (u32, bool)>) -> String {
    let mut v: Vec<(&String, &u32)> = Vec::new();
    for i in m.iter() {
        v.push((i.0, &i.1 .0));
    }
    v.sort_by(|(_, v1), (_, v2)| u32::cmp(v1, v2));
    v.iter()
        .map(|(k, v)| format!("{:#010X?} :: {}", v, k))
        .collect::<Vec<String>>()
        .join("\n")
}

pub fn remove_underscores(input: &str) -> String {
    String::from_iter(input.chars().filter(|c| *c != '_'))
}
