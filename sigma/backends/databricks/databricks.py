from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
# from sigma.pipelines.databricks import # TODO: add pipeline imports or delete this line
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List

class DatabricksSigmaBackend(TextQueryBackend):
    """databricks backend."""
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"

    # Generated query tokens
    token_separator: str = " "     # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    # Character used to quote field characters if field_quote_pattern matches (or not, depending on
    # field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote: ClassVar[str] = "'"
    # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is
    # always quoted if pattern is not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")
    # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    field_quote_pattern_negation: ClassVar[bool] = True

    ### Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    field_escape: ClassVar[str] = "\\"
    # Escape quote string defined in field_quote
    field_escape_quote: ClassVar[bool] = True
    # All matches of this pattern are prepended with the string contained in field_escape.
    field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")

    ## Values
    str_quote      : ClassVar[str] = "'"     # string quoting character (added as escaping character)
    escape_char    : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi : ClassVar[str] = ".*"     # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "."     # Character used as single-character wildcard
    add_escaped    : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars   : ClassVar[str] = ""      # Characters filtered
    bool_values    : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} like {value}%"
    endswith_expression  : ClassVar[str] = "endswith"
    contains_expression  : ClassVar[str] = "contains"
    # Special expression if wildcards can't be matched with the eq_token operator
    wildcard_match_expression: ClassVar[str] = "match"

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[str] = "{field} rlike '{regex}'"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    # List of strings that are escaped
    re_escape: ClassVar[Tuple[str]] = ("{}[]()\\+")

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"    # Character used as single wildcard
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = "cidrmatch({field}, {value})"
    # CIDR expression query as format string with placeholders {field} = in({list})
    cidr_in_list_expression: ClassVar[str] = "{field} in ({value})"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT : "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT : ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[str] = "{field} is null"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = True
    # Convert AND as in-expression
    convert_and_as_in: ClassVar[bool] = False
    # Values in list can contain wildcards. If set to False (default) only plain values are converted
    # into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = False
    # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[str] = "in"
    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    and_in_operator: ClassVar[str] = "contains-all"
    # List element separator
    list_separator: ClassVar[str] = ", "

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = "'{value}'"
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '{value}'
    # Expression for regular expression not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[str] = '_=~{value}'

    # Query finalization: appending and concatenating deferred query part
    # String used as separator between main query and deferred parts
    deferred_start: ClassVar[str] = "\n| "
    # String used to join multiple deferred query parts
    deferred_separator: ClassVar[str] = "\n| "
    # String used as query if final query only contains deferred expression
    deferred_only_query: ClassVar[str] = "*"

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html



    def finalize_query_format1(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # TODO: implement the per-query output for the output format format1 here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        return query

    def finalize_output_format1(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format format1 here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return "\n".join(queries)

    def finalize_query_format2(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # TODO: implement the per-query output for the output format format2 here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        return query

    def finalize_output_format2(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format format2 here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return "\n".join(queries)
