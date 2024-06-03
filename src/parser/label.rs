use super::{AstNode, LabelKind, Rule};

pub fn parse_label(
    pair: pest::iterators::Pair<Rule>,
    next_pair: Option<pest::iterators::Pair<Rule>>,
) -> AstNode {
    let mut name_pair = pair.clone();
    let kind = match pair.as_rule() {
        Rule::label_kind => {
            let pair_inner = pair.clone().into_inner().next().unwrap();
            name_pair = next_pair.unwrap();
            match pair_inner.as_rule() {
                Rule::label_external => LabelKind::External,
                Rule::label_global => LabelKind::Global,
                _ => unreachable!(),
            }
        }
        _ => LabelKind::Internal,
    };
    let node = AstNode::LabelDefine {
        name: name_pair.as_str().to_string(),
        kind,
    };
    node
}
