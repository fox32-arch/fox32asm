use std::fs;

use crate::{
    parser::{AstNode, Rule},
    SOURCE_PATH,
};

pub fn include_text_file(line_number: usize, text: &str, input_file: String) -> String {
    //println!("{}, {}", line_number, text);
    let path_start_index = text.find('"').unwrap() + 1;
    let path_end_index = text.len() - 1;
    let path_string = &text[path_start_index..path_end_index];
    //let path = canonicalize(path_string).expect(&format!("failed to include file \"{}\"", path_string));

    let mut source_path = SOURCE_PATH.lock().unwrap().clone();
    source_path.push(path_string);

    println!(
        "Including file as text data: {:#?}",
        source_path.file_name().expect("invalid filename")
    );

    let mut start_of_original_file = String::new();
    for (i, text) in input_file.lines().enumerate() {
        if i < line_number {
            start_of_original_file.push_str(text);
            start_of_original_file.push('\n');
        }
    }

    let mut included_file = fs::read_to_string(source_path)
        .expect(&format!("failed to include file \"{}\"", path_string));
    included_file.push('\n');

    let mut end_of_original_file = String::new();
    for (i, text) in input_file.lines().enumerate() {
        if i > line_number {
            end_of_original_file.push_str(text);
            end_of_original_file.push('\n');
        }
    }

    let mut final_file = String::new();

    final_file.push_str(&start_of_original_file);
    final_file.push_str(&included_file);
    final_file.push_str(&end_of_original_file);
    final_file
}

pub fn include_binary_file(pair: pest::iterators::Pair<Rule>, optional: bool) -> AstNode {
    let path_string = pair.into_inner().next().unwrap().as_str().trim();

    let mut source_path = SOURCE_PATH.lock().unwrap().clone();
    source_path.push(path_string);

    println!(
        "Including file as binary data: {:#?}",
        source_path.file_name().expect("invalid filename")
    );

    let binary = fs::read(&source_path);
    if binary.is_err() && optional {
        println!(
            "Optional include was not found: {:#?}",
            source_path.file_name().expect("invalid filename")
        );
        return AstNode::IncludedBinary(vec![]);
    } else if binary.is_err() {
        panic!("failed to include file");
    }

    AstNode::IncludedBinary(binary.unwrap())
}
