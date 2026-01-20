pub fn span_from_str<'i>(input: &'i str) -> pest::Span<'i> {
    pest::Span::new(input, 0, input.len()).unwrap()
}
