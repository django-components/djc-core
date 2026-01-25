from typing import TypeAlias

from djc_core.rust import template_parser
from djc_core.template_parser.compile import (
    TemplateStringResolver,
    VariableResolver,
    TranslationResolver,
    ExpressionResolver,
    FilterResolver,
    compile_tag,
    compile_value,
)
from djc_core.template_parser.parse import parse_tag

Comment: TypeAlias = template_parser.Comment
EndTag: TypeAlias = template_parser.EndTag
ForLoopTag: TypeAlias = template_parser.ForLoopTag
GenericTag: TypeAlias = template_parser.GenericTag
Tag: TypeAlias = template_parser.Tag
TagAttr: TypeAlias = template_parser.TagAttr
TagMeta: TypeAlias = template_parser.TagMeta
TagValue: TypeAlias = template_parser.TagValue
TagValueFilter: TypeAlias = template_parser.TagValueFilter
TemplateVersion: TypeAlias = template_parser.TemplateVersion
Token: TypeAlias = template_parser.Token
ValueChild: TypeAlias = template_parser.ValueChild
ValueKind: TypeAlias = template_parser.ValueKind
ParserConfig: TypeAlias = template_parser.ParserConfig
TagConfig: TypeAlias = template_parser.TagConfig
TagSectionSpec: TypeAlias = template_parser.TagSectionSpec
TagSpec: TypeAlias = template_parser.TagSpec
TagWithBodySpec: TypeAlias = template_parser.TagWithBodySpec

__all__ = [
    # PARSER
    "parse_tag",
    # COMPILER
    "compile_tag",
    "compile_value",
    "TemplateStringResolver",
    "VariableResolver",
    "TranslationResolver",
    "ExpressionResolver",
    "FilterResolver",
    # AST
    "Comment",
    "EndTag",
    "ForLoopTag",
    "GenericTag",
    "Tag",
    "TagAttr",
    "TagMeta",
    "TagValue",
    "TagValueFilter",
    "TemplateVersion",
    "Token",
    "ValueChild",
    "ValueKind",
    # CONFIG
    "ParserConfig",
    "TagConfig",
    "TagSectionSpec",
    "TagSpec",
    "TagWithBodySpec",
]
