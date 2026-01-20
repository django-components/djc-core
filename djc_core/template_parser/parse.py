from typing import Optional, Union

from djc_core.rust import template_parser


TagUnion = Union[template_parser.GenericTag, template_parser.ForLoopTag, template_parser.EndTag]


def parse_tag(input: str, config: Optional[template_parser.ParserConfig] = None) -> TagUnion:
    result = template_parser.parse_tag(input, config)
    # Unwrap Tag enum to specific Tag types
    unwrapped = result._0
    return unwrapped
