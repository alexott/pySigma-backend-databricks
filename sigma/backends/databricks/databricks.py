import json
import re
from typing import Optional, Pattern, Union, ClassVar, Tuple, List, Dict, Any, Type

import yaml
from sigma.conditions import ConditionItem, ConditionOR, ConditionAND, ConditionNOT, \
    ConditionFieldEqualsValueExpression
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaLevel
from sigma.types import SigmaCompareExpression, SigmaString, SigmaRegularExpression, CompareOperators
from sigma.types import SpecialChars


class DatabricksBackend(TextQueryBackend):
    """Databricks backend for PySigma."""
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    name: ClassVar[str] = "databricks"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain Databricks SQL queries",
        "dbsql": "Databricks SQL queries with additional metadata as comments",
        "detection_yaml": "Yaml markup for Alex's own detection framework",
    }
    # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user
    # interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    requires_pipeline: ClassVar[bool] = False

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[Type[ConditionItem], Type[ConditionItem], Type[ConditionItem]]] = (
        ConditionNOT, ConditionAND, ConditionOR
    )
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[Optional[str]] = "({expr})"

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[Optional[str]] = "OR"
    and_token: ClassVar[Optional[str]] = "AND"
    not_token: ClassVar[Optional[str]] = "NOT"
    eq_token: ClassVar[Optional[str]] = " = "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    # Character used to quote field characters if field_quote_pattern matches (or not, depending on
    # field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote: ClassVar[Optional[str]] = "`"
    # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is
    # always quoted if pattern is not set.
    field_quote_pattern: ClassVar[Optional[Pattern]] = re.compile("^(\\w|\\.)+$")
    # Negate field_quote_pattern result. Field name is quoted if pattern doesn't match if set to True (default).
    field_quote_pattern_negation: ClassVar[bool] = True

    # Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    field_escape: ClassVar[Optional[str]] = ""
    # Escape quote string defined in field_quote
    field_escape_quote: ClassVar[bool] = True
    # All matches of this pattern are prepended with the string contained in field_escape.
    field_escape_pattern: ClassVar[Optional[Pattern]] = re.compile("\\s")

    ## Values
    str_quote: ClassVar[str] = "'"  # string quoting character (added as escaping character)
    escape_char: ClassVar[Optional[str]] = "\\"  # Escaping character for special characters inside string
    wildcard_multi: ClassVar[Optional[str]] = ".*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[Optional[str]] = "."  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = "\\'"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, Optional[str]]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[Optional[str]] = "startswith(lower({field}), lower({value}))"
    endswith_expression: ClassVar[Optional[str]] = "endswith(lower({field}), lower({value}))"
    contains_expression: ClassVar[Optional[str]] = "contains(lower({field}), lower({value}))"
    # Special expression if wildcards can't be matched with the eq_token operator
    wildcard_match_expression: ClassVar[Optional[str]] = "lower({field}) regexp {value}"

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[Optional[str]] = "{field} rlike '{regex}'"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[Optional[str]] = "\\"
    # List of strings that are escaped
    re_escape: ClassVar[Tuple[str]] = ("{}[]()\\+",)
    # Regular expression flags. We rely on the default implementation of the backend to handle them.
    re_flag_prefix: bool = True

    # cidr expressions
    # TODO: fix that
    cidr_wildcard: ClassVar[Optional[str]] = "*"  # Character used as single wildcard
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[Optional[str]] = "cidrmatch({field}, '{value}')"
    # CIDR expression query as format string with placeholders {field} = in({list})
    cidr_in_list_expression: ClassVar[Optional[str]] = "{field} in ({value})"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[Optional[str]] = "{field} {operator} {value}"
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Optional[Dict[CompareOperators, str]]] = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[Optional[str]] = "{field} is null"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = False
    # Convert AND as in-expression
    convert_and_as_in: ClassVar[bool] = False
    # Values in list can contain wildcards. If set to False (default) only plain values are converted
    # into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = False
    # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[Optional[str]] = "lower({field}) {op} ({list})"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[Optional[str]] = "in"
    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    and_in_operator: ClassVar[Optional[str]] = "contains-all"
    # List element separator
    list_separator: ClassVar[Optional[str]] = ", "

    # Field equals field comparison expression
    # Expression for field to field comparison as format string with placeholders {field1} and {field2}
    field_equals_field_expression: ClassVar[Optional[str]] = "{field1} = {field2}"

    # OR optimization: Convert repeated OR operations with contains/startswith/endswith into regex
    # Enable optimization of OR conditions as regex expressions
    optimize_or_as_regex: ClassVar[bool] = True
    # Minimum number of OR terms required to trigger regex optimization (set to 3 to avoid micro-optimizations)
    min_or_terms_for_optimization: ClassVar[int] = 3

    # TODO: think how to handle them? We really can't match them without field...
    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[Optional[str]] = "{value}"
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[Optional[str]] = '{value}'
    # Expression for regular expression not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[Optional[str]] = '_=~{value}'

    # Field name containing the raw/full log line for unbound keyword searches
    raw_log_field: str = "raw"

    # Query finalization: appending and concatenating deferred query part
    # String used as separator between main query and deferred parts
    deferred_start: ClassVar[Optional[str]] = "\n| "
    # String used to join multiple deferred query parts
    deferred_separator: ClassVar[Optional[str]] = "\n| "
    # String used as query if final query only contains deferred expression
    deferred_only_query: ClassVar[Optional[str]] = "*"

    def __init__(self, processing_pipeline=None, collect_errors=False, raw_log_field: Optional[str] = None, **kwargs):
        """Initialize Databricks backend with optional raw log field configuration."""
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        if raw_log_field:
            self.raw_log_field = raw_log_field

    def make_sql_string(self, s: SigmaString):
        converted = s.convert(
            self.escape_char,
            None,
            None,
            (self.str_quote or "") + self.add_escaped,
            self.filter_chars,
        )
        return self.quote_string(converted)

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression,
                                           state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        if not isinstance(cond.value, SigmaString):
            raise TypeError(f"cond.value type isn't SigmaString: {type(cond.value)}")
        
        # Type narrowing for Pylance
        sigma_value: SigmaString = cond.value
        
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression is not None  # 'startswith' operator is defined in backend
                and sigma_value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and not sigma_value[:-1].contains_special()  # Remainder of string doesn't contain special characters
            ):
                expr = self.startswith_expression  # If all conditions are fulfilled, use 'startswith' operator
                # instead of equal token
                value = self.make_sql_string(sigma_value[:-1])
            elif (
                # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contain further
                # special characters
                self.endswith_expression is not None
                and sigma_value.startswith(SpecialChars.WILDCARD_MULTI)
                and not sigma_value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = self.make_sql_string(sigma_value[1:])
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and sigma_value.startswith(SpecialChars.WILDCARD_MULTI)
                and sigma_value.endswith(SpecialChars.WILDCARD_MULTI)
                and not sigma_value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = self.make_sql_string(sigma_value[1:-1])
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None
                and sigma_value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = self.convert_value_str(sigma_value, state)
            else:  # We have just plain string
                expr = "lower({field}) = lower({value})"
                value = self.make_sql_string(sigma_value)

            return expr.format(field=self.escape_and_quote_field(cond.field),
                               value=value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the "
                                      "backend.")

    def convert_condition_val_str(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of unbound string values (keywords without field names)"""
        if not self.raw_log_field:
            raise ValueError("Unbound keyword search requires raw_log_field to be configured")

        # Use raw log field for keyword search
        field = self.escape_and_quote_field(self.raw_log_field)
        value = cond.value
        
        # Type narrowing: ensure value is SigmaString
        if not isinstance(value, SigmaString):
            raise TypeError(f"Expected SigmaString, got {type(value)}")

        # Handle wildcards similar to field-based logic
        if (self.contains_expression is not None
            and value.startswith(SpecialChars.WILDCARD_MULTI)
            and value.endswith(SpecialChars.WILDCARD_MULTI)
            and not value[1:-1].contains_special()):
            # *keyword* -> contains()
            val_str = self.make_sql_string(value[1:-1])
            return self.contains_expression.format(field=field, value=val_str)
        elif (self.startswith_expression is not None
              and value.endswith(SpecialChars.WILDCARD_MULTI)
              and not value[:-1].contains_special()):
            # keyword* -> startswith()
            val_str = self.make_sql_string(value[:-1])
            return self.startswith_expression.format(field=field, value=val_str)
        elif (self.endswith_expression is not None
              and value.startswith(SpecialChars.WILDCARD_MULTI)
              and not value[1:].contains_special()):
            # *keyword -> endswith()
            val_str = self.make_sql_string(value[1:])
            return self.endswith_expression.format(field=field, value=val_str)
        elif (self.wildcard_match_expression is not None
              and value.contains_special()):
            # Complex wildcards -> regexp
            val_str = self.convert_value_str(value, state)
            return self.wildcard_match_expression.format(field=field, value=val_str)
        else:
            # Plain keyword -> contains() (most common case)
            val_str = self.make_sql_string(value)
            if self.contains_expression:
                return self.contains_expression.format(field=field, value=val_str)
            raise ValueError("contains_expression is not defined")

    def convert_condition_val_re(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of unbound regex values"""
        if not self.raw_log_field:
            raise ValueError("Unbound regex search requires raw_log_field to be configured")

        # Type narrowing: ensure value is SigmaRegularExpression
        if not isinstance(cond.value, SigmaRegularExpression):
            raise TypeError(f"Expected SigmaRegularExpression, got {type(cond.value)}")

        field = self.escape_and_quote_field(self.raw_log_field)
        if self.re_expression:
            return self.re_expression.format(field=field, regex=cond.value.regexp)
        raise ValueError("re_expression is not defined")

    def convert_condition_val_num(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of unbound numeric values"""
        if not self.raw_log_field:
            raise ValueError("Unbound numeric search requires raw_log_field to be configured")

        # Convert number to string search in raw log
        field = self.escape_and_quote_field(self.raw_log_field)
        value = self.make_sql_string(SigmaString(str(cond.value)))
        if self.contains_expression:
            return self.contains_expression.format(field=field, value=value)
        raise ValueError("contains_expression is not defined")

    def _analyze_or_for_regex_optimization(
        self, cond: ConditionOR
    ) -> Optional[Tuple[str, str, List[str]]]:
        """
        Analyze an OR condition to determine if it can be optimized as a regex expression.

        Returns a tuple of (field_name, pattern_type, values) if optimization is possible,
        where pattern_type is one of: 'contains', 'startswith', 'endswith'.
        Returns None if optimization is not applicable.
        """
        if not self.optimize_or_as_regex:
            return None

        # Check if we have enough terms to optimize
        if len(cond.args) < self.min_or_terms_for_optimization:
            return None

        # All args must be ConditionFieldEqualsValueExpression
        if not all(isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args):
            return None

        # Extract field names and check they're all the same
        # Type narrowing: at this point we know all args are ConditionFieldEqualsValueExpression
        field_exprs = [arg for arg in cond.args if isinstance(arg, ConditionFieldEqualsValueExpression)]
        fields = [arg.field for arg in field_exprs]
        if len(set(fields)) != 1:
            return None  # Different fields, can't optimize

        field_name = fields[0]

        # Check all values are SigmaString and determine pattern type
        pattern_type: Optional[str] = None
        values: List[str] = []

        for arg in field_exprs:
            if not isinstance(arg.value, SigmaString):
                return None  # Not a string value, can't optimize

            value = arg.value

            # Determine the pattern type based on wildcards
            if value.startswith(SpecialChars.WILDCARD_MULTI) and value.endswith(SpecialChars.WILDCARD_MULTI):
                # Contains pattern: *value*
                current_pattern = 'contains'
                # Extract the actual value without wildcards
                actual_value = str(value)[1:-1]
            elif value.startswith(SpecialChars.WILDCARD_MULTI):
                # Endswith pattern: *value
                current_pattern = 'endswith'
                actual_value = str(value)[1:]
            elif value.endswith(SpecialChars.WILDCARD_MULTI):
                # Startswith pattern: value*
                current_pattern = 'startswith'
                actual_value = str(value)[:-1]
            else:
                # No wildcards, can't optimize as regex
                return None

            # Check if pattern type is consistent
            if pattern_type is None:
                pattern_type = current_pattern
            elif pattern_type != current_pattern:
                # Mixed patterns, can't optimize into single regex
                return None

            values.append(actual_value)

        # Ensure pattern_type is not None before returning
        if pattern_type is None:
            return None
        
        return (field_name, pattern_type, values)

    def _build_regex_pattern(self, pattern_type: str, values: List[str]) -> str:
        """
        Build a case-insensitive regex pattern for the given pattern type and values.

        Uses (?i) flag for case-insensitivity (Java regex compatible).
        """
        # Escape each value for use in regex (Java regex compatible)
        escaped_values = [re.escape(str(v)) for v in values]

        # Join values with pipe (OR in regex)
        alternatives = '|'.join(escaped_values)

        # Build pattern based on type
        if pattern_type == 'contains':
            return f'(?i).*({alternatives}).*'
        elif pattern_type == 'startswith':
            return f'(?i)({alternatives}).*'
        elif pattern_type == 'endswith':
            return f'(?i).*({alternatives})'
        else:
            raise ValueError(f"Unknown pattern type: {pattern_type}")

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """
        Conversion of OR conditions with optimization for repeated string matching patterns.

        If multiple OR conditions match the same field with the same pattern type
        (contains/startswith/endswith), they are optimized into a single regex expression.
        """
        # Try to optimize as regex
        optimization = self._analyze_or_for_regex_optimization(cond)

        if optimization:
            field_name, pattern_type, values = optimization

            # Build the optimized regex pattern
            regex_pattern = self._build_regex_pattern(pattern_type, values)

            # Use the re_expression format with escaped field name
            field = self.escape_and_quote_field(field_name)
            if self.re_expression:
                return self.re_expression.format(field=field, regex=regex_pattern)
            raise ValueError("re_expression is not defined")

        # Fall back to default OR conversion
        return super().convert_condition_or(cond, state)

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    @staticmethod
    def finalize_query_dbsql(rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        rule_status = (rule.status.name if rule.status else "test").lower()
        title = rule.title.replace('\n', ' ')
        return f"-- title: \"{title}\". status: {rule_status}\n{query}"

    @staticmethod
    def finalize_output_dbsql(queries: List[str]) -> Any:
        return "\n\n".join(queries)

    @staticmethod
    def finalize_query_detection_yaml(rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        statuses = {"experimental": "test", "stable": "release"}
        levels = {SigmaLevel.INFORMATIONAL.name: 0, SigmaLevel.LOW.name: 10, SigmaLevel.MEDIUM.name: 30,
                  SigmaLevel.HIGH.name: 50, SigmaLevel.CRITICAL.name: 90}
        rule_status = (rule.status.name if rule.status else "test").lower()
        d: Dict[str, Any] = {"name": rule.title,
             "sql": query,
             "status": statuses.get(rule_status, rule_status),
             "template": rule.title,
             }
        if rule.level:
            level = levels.get(rule.level.name)
            if level:
                d["severity"] = level
        return json.dumps(d)

    @staticmethod
    def finalize_output_detection_yaml(queries: List[str]) -> Any:
        data: Dict[str, Any] = {"description": "Detections generated from Sigma rules"}
        detections: List[Any] = []
        for query in queries:
            d = json.loads(query)
            if d["status"] == "deprecated" or d["status"] == "unsupported" or d["sql"] == "":
                continue
            detections.append(d)
        data["detections"] = detections
        return yaml.dump(data, default_flow_style=False)
