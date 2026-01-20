# This file adds typing for the API exposed from Rust via maturin.
#
# Since the Rust code exposed to Python is scoped under modules, we need to define
# the API as class attributes, e.g.
#
# ```py
# class template_parser:
#     class Tag:
#         ...
# ```
#
# So that in Python we can access it as:
#
# ```py
# from djc_core.rust import template_parser
# template_parser.Tag(...)
# ```
#
# Notes:
# - Functions without `self` are treated as module-level functions.
#   This matches how typeshed defines modules.

from typing import List, Literal, Optional, Set, Tuple, Union

########################################################
# Template parser
########################################################

class template_parser:
    def parse_tag(
        input: str, config: "Optional[template_parser.ParserConfig]" = None
    ) -> "template_parser.Tag": ...
    def compile_tag_attrs(attributes: "List[template_parser.TagAttr]") -> str: ...
    def compile_value(value: "template_parser.TagValue") -> str: ...

    #########################
    # AST
    #########################

    class ValueKind:
        def __init__(
            self,
            kind: Literal[
                "list",
                "dict",
                "int",
                "float",
                "variable",
                "template_string",
                "translation",
                "string",
                "python_expr",
            ],
        ) -> None: ...

    class Token:
        """Represents a token with position information"""
        def __init__(
            self,
            content: str,
            start_index: int,
            end_index: int,
            line_col: Tuple[int, int],
        ) -> None: ...
        content: str
        start_index: int
        end_index: int
        line_col: Tuple[int, int]

    class ValueChild:
        """Child value that can be either a TagValue or a Template"""
        def __init__(self, obj: Union["template_parser.TagValue"]) -> None: ...

    class TagValueFilter:
        def __init__(
            self,
            token: template_parser.Token,
            name: template_parser.Token,
            arg: Optional["template_parser.TagValue"],
        ) -> None: ...
        token: template_parser.Token
        name: template_parser.Token
        arg: Optional["template_parser.TagValue"]

    class TagValue:
        def __init__(
            self,
            token: template_parser.Token,
            value: template_parser.Token,
            kind: template_parser.ValueKind,
            spread: Optional[str],
            filters: List[template_parser.TagValueFilter],
            used_variables: List[template_parser.Token],
            assigned_variables: List[template_parser.Token],
            children: List[template_parser.ValueChild],
        ) -> None: ...
        token: template_parser.Token  # Entire value span including filters and spread
        value: (
            template_parser.Token
        )  # Just the value itself (excluding filters and spread)
        children: List[
            template_parser.ValueChild
        ]  # Children of this TagValue (list items, dict entries, or Template for TemplateString)
        kind: template_parser.ValueKind
        spread: Optional[str]
        filters: List[template_parser.TagValueFilter]
        used_variables: List[
            template_parser.Token
        ]  # Context variables that this TagValue needs
        assigned_variables: List[
            template_parser.Token
        ]  # Context variables that this TagValue introduces

    class TagAttr:
        def __init__(
            self,
            token: template_parser.Token,
            key: Optional[template_parser.Token],
            value: template_parser.TagValue,
            is_flag: bool,
        ) -> None: ...
        token: template_parser.Token  # Entire attribute span (key + value with filters)
        key: Optional[template_parser.Token]  # Key token if key-value pair
        value: template_parser.TagValue
        is_flag: bool

    class TagMeta:
        """Common tag metadata shared by all tag types"""
        def __init__(
            self,
            token: template_parser.Token,
            name: template_parser.Token,
            used_variables: List[template_parser.Token],
            assigned_variables: List[template_parser.Token],
        ) -> None: ...
        token: (
            template_parser.Token
        )  # Token containing the entire tag span including delimiters
        name: template_parser.Token  # Token for the tag name
        used_variables: List[
            template_parser.Token
        ]  # Context variables that this Tag needs
        assigned_variables: List[
            template_parser.Token
        ]  # Context variables that this Tag introduces

    class GenericTag:
        """Represents a template tag, including its name, attributes, and other metadata"""
        def __init__(
            self,
            token: template_parser.Token,
            name: template_parser.Token,
            attrs: List[template_parser.TagAttr],
            is_self_closing: bool,
            used_variables: List[template_parser.Token],
            assigned_variables: List[template_parser.Token],
        ) -> None: ...
        meta: template_parser.TagMeta  # Common tag metadata
        attrs: List[template_parser.TagAttr]  # A list of attributes passed to the tag
        is_self_closing: bool  # Whether the tag is self-closing

    class ForLoopTag:
        """Represents a for loop tag: `{% for item in items %}`"""
        def __init__(
            self,
            token: template_parser.Token,
            name: template_parser.Token,
            targets: List[template_parser.Token],
            iterable: template_parser.TagValue,
            used_variables: List[template_parser.Token],
            assigned_variables: List[template_parser.Token],
        ) -> None: ...
        meta: template_parser.TagMeta  # Common tag metadata
        targets: List[
            template_parser.Token
        ]  # The loop variable names (e.g., ["item"] or ["x", "y", "z"])
        iterable: template_parser.TagValue  # The iterable expression

    class EndTag:
        """Represents an end tag (e.g., `{% endif %}`, `{% endfor %}`, `</slot>`)"""
        def __init__(
            self, token: template_parser.Token, name: template_parser.Token
        ) -> None: ...
        meta: template_parser.TagMeta  # Common tag metadata

    class Tag:
        """Represents a template tag - either a generic tag, a for loop tag, or an end tag

        This is an enum that can be:
        - Generic(GenericTag) - A regular tag with attributes
        - ForLoop(ForLoopTag) - A for loop tag
        - End(EndTag) - An end tag

        The constructor creates a Generic tag. Use as_generic(), as_forloop(), or as_end() to access variants.
        """
        def __init__(
            self,
            token: template_parser.Token,
            name: template_parser.Token,
            attrs: List[template_parser.TagAttr],
            is_self_closing: bool,
            used_variables: List[template_parser.Token],
            assigned_variables: List[template_parser.Token],
        ) -> None: ...
        def as_generic(
            self,
        ) -> Optional[template_parser.GenericTag]: ...  # Get as GenericTag if it is one
        def as_forloop(
            self,
        ) -> Optional[template_parser.ForLoopTag]: ...  # Get as ForLoopTag if it is one
        def as_end(
            self,
        ) -> Optional[template_parser.EndTag]: ...  # Get as EndTag if it is one

    class Comment:
        """Represents a Django template comment `{# ... #}` or `{% comment %}...{% endcomment %}`"""
        def __init__(
            self, token: template_parser.Token, value: template_parser.Token
        ) -> None: ...
        token: template_parser.Token  # Entire comment span including delimiters
        value: template_parser.Token  # Comment text without delimiters

    class TemplateVersion:
        """Template version enum"""
        def __init__(
            self, version: Literal["1", "v1", "2", "v2", "3", "v3"]
        ) -> None: ...
        v1: "template_parser.TemplateVersion"  # class attribute
        v2: "template_parser.TemplateVersion"  # class attribute
        v3: "template_parser.TemplateVersion"  # class attribute

    #########################
    # Parser config
    #########################

    class TagSpec:
        """Basic metadata for a tag, e.g. `{% if %}`"""
        def __init__(self, tag_name: str, flags: Set[str]) -> None: ...
        tag_name: str  # The tag name
        flags: Set[str]  # Flags that this tag can accept

    class TagSectionSpec:
        """Metadata for a tag section

        Represents a sub-tag that splits the parent's tag body into multiple sections.
        For example, `{% elif %}` and `{% else %}` are sections for the `{% if %}` tag.
        """
        def __init__(
            self, tag: "template_parser.TagSpec", repeatable: bool
        ) -> None: ...
        tag: "template_parser.TagSpec"  # The tag specification (name and flags)
        repeatable: bool  # Whether this tag can appear multiple times (true) or only once (false)

    class TagWithBodySpec:
        """Metadata for a tag with body (and optionally extra sections).

        For example, `{% if %}` can contain `{% elif %}` and `{% else %}` sections.
        """
        def __init__(
            self,
            tag: "template_parser.TagSpec",
            sections: List["template_parser.TagSectionSpec"],
        ) -> None: ...
        tag: "template_parser.TagSpec"  # The parent tag specification (name and flags)
        sections: List[
            "template_parser.TagSectionSpec"
        ]  # Sections of related tags that can appear within this tag's body

    class TagConfig:
        """Config for a tag - This sets how the parser will parse the tag.

        This is a union type that differentiates between:
        - Tags without bodies (just a single tag, e.g., `{% lorem %}`)
        - Tags with bodies that can contain sections (e.g., `{% if %}` with `{% elif %}` and `{% else %}`)
        """
        def __init__(
            self,
            tag: "template_parser.TagSpec",
            sections: Optional[List["template_parser.TagSectionSpec"]] = None,
        ) -> None: ...
        def get_flags(self) -> Set[str]: ...  # Get the flags for this tag config

    class ParserConfig:
        """Parser config

        This struct holds info on how the parser will parse the template / tags.
        It can be constructed from Python or Rust.
        """
        def __init__(self, version: "template_parser.TemplateVersion") -> None: ...
        version: "template_parser.TemplateVersion"  # Template version
        def set_tag(
            self, tag_config: "template_parser.TagConfig"
        ) -> None: ...  # Set config for a tag
        def get_tag(
            self, tag_name: str
        ) -> Optional["template_parser.TagConfig"]: ...  # Get config for a tag
