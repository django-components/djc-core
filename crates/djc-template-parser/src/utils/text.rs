/// Indents a body of text with a given indentation level
pub(crate) fn indent_body(body: &str, indent_level: usize) -> String {
    let indent = " ".repeat(indent_level);
    body.lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("{}{}", indent, line)
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}
