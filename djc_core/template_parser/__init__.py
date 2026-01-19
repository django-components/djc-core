import sys

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

# TODO - Remove this conditional once Django drops support for Python 3.8 and 3.9
if sys.version_info >= (3, 10):
    from typing import TypeAlias

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
else:
    Comment = template_parser.Comment
    EndTag = template_parser.EndTag
    ForLoopTag = template_parser.ForLoopTag
    GenericTag = template_parser.GenericTag
    Tag = template_parser.Tag
    TagAttr = template_parser.TagAttr
    TagMeta = template_parser.TagMeta
    TagValue = template_parser.TagValue
    TagValueFilter = template_parser.TagValueFilter
    TemplateVersion = template_parser.TemplateVersion
    Token = template_parser.Token
    ValueChild = template_parser.ValueChild
    ValueKind = template_parser.ValueKind
    ParserConfig = template_parser.ParserConfig
    TagConfig = template_parser.TagConfig
    TagSectionSpec = template_parser.TagSectionSpec
    TagSpec = template_parser.TagSpec
    TagWithBodySpec = template_parser.TagWithBodySpec

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
