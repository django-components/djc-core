# ruff: noqa: ANN201,ARG005,S101,S105,S106,E501
from typing import Any
from unittest.mock import Mock

from djc_core.template_parser import (
    TagValue,
    compile_value,
    parse_tag,
)

###############################
# RESOLVERS
###############################


def expr_resolver(ctx, src, token, filters, tags, expr):
    return f"EXPR_RESOLVED:{expr}"


def template_resolver(ctx, src, token, filters, tags, template):
    return f"TEMPLATE_RESOLVED:{template}"


def translation_resolver(ctx, src, token, filters, tags, text):
    return f"TRANSLATION_RESOLVED:{text}"


###############################
# HELPERS
###############################


def _upper_filter(value, arg):
    if isinstance(value, (list, tuple)):
        return [item.upper() for item in value]
    elif isinstance(value, dict):
        return {key: value.upper() for key, value in value.items()}
    return value.upper()


def _simple_compile_value(value: TagValue, source: str):
    return compile_value(
        value,
        source,
        filters={
            "upper": _upper_filter,
            "add": lambda value, arg: value + arg,
            "round": lambda value, arg: round(value, arg),
        },
        tags={},
        template_string=template_resolver,
        expr=expr_resolver,
        translation=translation_resolver,
        filter=lambda ctx, src, token, filters, tags, name, value, arg: filters[name](
            value, arg
        ),
        variable=lambda ctx, src, token, filters, tags, var: ctx[var],
    )


############################################################
# TESTS
############################################################


# Test that resolvers are called correctly
class TestResolvers:
    def _setup_resolver_test(self, tag_content: str, context: Any):
        value = parse_tag(tag_content).attrs[0].value

        # Mock variable resolver to return different values for different variables
        def variable_side_effect(ctx, src, token, filters, tags, var):
            if var == "my_var":
                return "test_value"
            elif var == "arg":
                return "arg_value"
            return None

        mock_variable = Mock(side_effect=variable_side_effect)
        mock_template_string = Mock(return_value="resolved_template")
        mock_translation = Mock(return_value="resolved_translation")
        mock_filter = Mock(return_value="resolved_filter")
        mock_expr = Mock(return_value="resolved_expr")

        filters = {"my_filter": lambda *args, **kwargs: "<my_filter>"}
        tags = {"my_tag": lambda *args, **kwargs: "<my_tag>"}

        tag_func = compile_value(
            value,
            tag_content,
            filters=filters,
            tags=tags,
            variable=mock_variable,
            template_string=mock_template_string,
            translation=mock_translation,
            filter=mock_filter,
            expr=mock_expr,
        )

        tag_func(context)

        return (
            mock_variable,
            mock_template_string,
            mock_translation,
            mock_filter,
            mock_expr,
            filters,
            tags,
        )

    def test_variable_resolver(self):
        context = {"my_var": "test"}
        tag_content = "{% component my_var %}"
        (
            mock_variable,
            mock_template_string,
            mock_translation,
            mock_filter,
            mock_expr,
            filters,
            tags,
        ) = self._setup_resolver_test(tag_content, context)

        # Assert variable resolver was called once with expected arguments
        mock_variable.assert_called_once()
        call_args = mock_variable.call_args
        assert call_args[0][0] == context  # context
        assert call_args[0][1] == tag_content  # source
        assert call_args[0][2] == (13, 19)  # token (start_index, end_index)
        assert call_args[0][3] == filters  # filters
        assert call_args[0][4] == tags  # tags
        assert call_args[0][5] == "my_var"  # var

        # Other resolvers should not be called
        mock_template_string.assert_not_called()
        mock_translation.assert_not_called()
        mock_filter.assert_not_called()
        mock_expr.assert_not_called()

    def test_template_string_resolver(self):
        context = {}
        tag_content = "{% component '{% lorem w 4 %}' %}"
        (
            mock_variable,
            mock_template_string,
            mock_translation,
            mock_filter,
            mock_expr,
            filters,
            tags,
        ) = self._setup_resolver_test(tag_content, context)

        # Assert template_string resolver was called once with expected arguments
        mock_template_string.assert_called_once()
        call_args = mock_template_string.call_args
        assert call_args[0][0] == context  # context
        assert call_args[0][1] == tag_content  # source
        assert call_args[0][2] == (13, 30)  # token (start_index, end_index)
        assert call_args[0][3] == filters  # filters
        assert call_args[0][4] == tags  # tags
        assert call_args[0][5] == "{% lorem w 4 %}"  # expr

        # Other resolvers should not be called
        mock_variable.assert_not_called()
        mock_translation.assert_not_called()
        mock_filter.assert_not_called()
        mock_expr.assert_not_called()

    def test_translation_resolver(self):
        context = {}
        tag_content = '{% component _("hello world") %}'
        (
            mock_variable,
            mock_template_string,
            mock_translation,
            mock_filter,
            mock_expr,
            filters,
            tags,
        ) = self._setup_resolver_test(tag_content, context)

        # Assert translation resolver was called once with expected arguments
        mock_translation.assert_called_once()
        call_args = mock_translation.call_args
        assert call_args[0][0] == context  # context
        assert call_args[0][1] == tag_content  # source
        assert call_args[0][2] == (13, 29)  # token (start_index, end_index)
        assert call_args[0][3] == filters  # filters
        assert call_args[0][4] == tags  # tags
        assert call_args[0][5] == "hello world"  # text (inner string without quotes)

        # Other resolvers should not be called
        mock_variable.assert_not_called()
        mock_template_string.assert_not_called()
        mock_filter.assert_not_called()
        mock_expr.assert_not_called()

    def test_expr_resolver(self):
        context = {}
        tag_content = "{% component (1 + 2) %}"
        (
            mock_variable,
            mock_template_string,
            mock_translation,
            mock_filter,
            mock_expr,
            filters,
            tags,
        ) = self._setup_resolver_test(tag_content, context)

        # Assert expr resolver was called once with expected arguments
        mock_expr.assert_called_once()
        call_args = mock_expr.call_args
        assert call_args[0][0] == context  # context
        assert call_args[0][1] == tag_content  # source
        assert call_args[0][2] == (13, 20)  # token (start_index, end_index)
        assert call_args[0][3] == filters  # filters
        assert call_args[0][4] == tags  # tags
        assert call_args[0][5] == "(1 + 2)"  # code

        # Other resolvers should not be called
        mock_variable.assert_not_called()
        mock_template_string.assert_not_called()
        mock_translation.assert_not_called()
        mock_filter.assert_not_called()

    def test_filter_resolver(self):
        context = {}
        tag_content = "{% component my_var|upper:arg %}"
        (
            mock_variable,
            mock_template_string,
            mock_translation,
            mock_filter,
            mock_expr,
            filters,
            tags,
        ) = self._setup_resolver_test(tag_content, context)

        # Assert filter resolver was called once with expected arguments
        mock_filter.assert_called_once()
        call_args = mock_filter.call_args
        assert call_args[0][0] == context  # context
        assert call_args[0][1] == tag_content  # source
        assert call_args[0][2] == (
            19,
            29,
        )  # token (start_index, end_index) - filter token |upper:arg
        assert call_args[0][3] == filters  # filters
        assert call_args[0][4] == tags  # tags
        assert call_args[0][5] == "upper"  # name
        assert call_args[0][6] == "test_value"  # value (from variable resolver)
        assert call_args[0][7] == "arg_value"  # arg (from variable resolver)

        # Variable resolver should be called twice (for the value and arg)
        assert mock_variable.call_count == 2

        # Other resolvers should not be called
        mock_template_string.assert_not_called()
        mock_translation.assert_not_called()
        mock_expr.assert_not_called()


class TestValueCompiler:
    def test_string_value(self):
        tag_content = "{% component 'hello world'|upper %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({})

        assert result == "HELLO WORLD"

    def test_int_value(self):
        tag_content = "{% component 42|add:10 %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({})

        assert result == 52

    def test_float_value(self):
        tag_content = "{% component 3.1415|round:2 %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({})

        assert result == 3.14

    def test_variable_value(self):
        tag_content = "{% component my_var|upper %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({"my_var": "test_value"})

        assert result == "TEST_VALUE"

    def test_template_string_value(self):
        tag_content = "{% component '{% lorem w 4 %}'|upper %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({})

        assert result == "TEMPLATE_RESOLVED:{% LOREM W 4 %}"

    def test_translation_value(self):
        tag_content = '{% component _("hello")|upper %}'
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({})

        assert result == "TRANSLATION_RESOLVED:HELLO"

    def test_python_expr_value(self):
        tag_content = "{% component (1 + 2)|add:' :)' %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({})

        assert result == "EXPR_RESOLVED:(1 + 2) :)"

    def test_list_value(self):
        tag_content = "{% component ['one', 'two', my_var]|upper %}"
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({"my_var": "car"})

        assert result == ["ONE", "TWO", "CAR"]

    def test_dict_value(self):
        tag_content = '{% component {"key": "val", "num": my_var}|upper %}'
        tag = parse_tag(tag_content)
        value = tag.attrs[0].value
        value_func = _simple_compile_value(value, tag_content)
        result = value_func({"my_var": "car"})

        assert result == {"key": "VAL", "num": "CAR"}
