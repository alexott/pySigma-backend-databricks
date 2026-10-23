"""Databricks/Apache Spark SQL backend for pySigma, including Lakewatch output format."""

import copy
import json
import re
from typing import Any, ClassVar, Dict, List, Optional, Pattern, Tuple, Type, Union

import yaml
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionItem, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaConversionError
from sigma.rule import SigmaLevel, SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCompareExpression,
    SigmaExists,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from .lakewatch_maps import (
    FIDELITY_MAP,
    SEVERITY_MAP,
    V2_RULE_NAME_MAX_LEN,
    build_mitre_mapping,
    resolve_ocsf_table,
    to_v2_fidelity,
    to_v2_mitre,
    to_v2_references,
    to_v2_rule_name,
)
from .ocsf_fields import OcsfPath, split_ocsf_path


class _LakewatchDumper(yaml.SafeDumper):
    """YAML dumper that renders multi-line strings as literal block scalars."""


def _represent_str_block(dumper: yaml.SafeDumper, data: str):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_LakewatchDumper.add_representer(str, _represent_str_block)


class DatabricksBackend(TextQueryBackend):
    """Databricks backend for PySigma."""

    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    name: ClassVar[str] = "databricks"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain Databricks SQL queries",
        "dbsql": "Databricks SQL queries with additional metadata as comments",
        "detection_yaml": "Yaml markup for Alex's own detection framework",
        "lakewatch": "Lakewatch detection rules (v1 kind: Rule YAML)",
        "lakewatch_v2": "Lakewatch detection rules (v2 format, Unity Catalog governed)",
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
    # Special expression if wildcards can't be matched with the eq_token operator. {value} is a quoted SQL string
    # with an anchored, case-insensitive regex built by make_wildcard_regex
    wildcard_match_expression: ClassVar[Optional[str]] = "{field} rlike {value}"

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[Optional[str]] = "{field} rlike '{regex}'"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[Optional[str]] = "\\"
    # List of strings that are escaped. The regex ends up inside a SQL string literal, so the escape char itself
    # (escaped by default) and the string quote must be escaped for Spark's string literal parsing.
    re_escape: ClassVar[Tuple[str]] = ("'",)
    # Regular expression flags. We rely on the default implementation of the backend to handle them.
    re_flag_prefix: bool = True

    # cidr expressions
    cidr_wildcard: ClassVar[Optional[str]] = "*"  # Character used as single wildcard
    # CIDR expression query as format string with placeholders {field}, {value} (whole CIDR), {network},
    # {prefixlen} and {netmask}. Uses built-in Databricks functions (DBR 18.2+); try_ip_as_binary turns
    # invalid IP values into NULL instead of failing the query (TODO: NULL also doesn't match under NOT,
    # consider wrapping into coalesce(..., false)). Override with the cidr_expression backend
    # option for other Spark SQL engines, e.g. "cidrmatch({field}, '{value}')" with a custom UDF.
    cidr_expression: ClassVar[Optional[str]] = "ip_cidr_contains('{value}', try_ip_as_binary({field}))"
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
    # Expressions for field existence (|exists modifier) as format strings with {field} placeholder for field name
    field_exists_expression: ClassVar[Optional[str]] = "{field} is not null"
    field_not_exists_expression: ClassVar[Optional[str]] = "{field} is null"

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
    # Raw event field of OCSF events, used for keyword searches when the target is OCSF
    ocsf_raw_log_field: ClassVar[str] = "raw_data"
    # Placeholder field name for the element-level part of an OCSF field rendered by the backend
    _ocsf_inner_field: ClassVar[str] = "\x00ocsf_inner_field"

    # Query finalization: appending and concatenating deferred query part
    # String used as separator between main query and deferred parts
    deferred_start: ClassVar[Optional[str]] = "\n| "
    # String used to join multiple deferred query parts
    deferred_separator: ClassVar[Optional[str]] = "\n| "
    # String used as query if final query only contains deferred expression
    deferred_only_query: ClassVar[Optional[str]] = "*"

    def __init__(self, processing_pipeline=None, collect_errors=False,
                 raw_log_field: Optional[str] = None, table_name: Optional[str] = None,
                 lookback: str = "25 HOUR", schedule: str = "24h",
                 compute_group: str = "automatic", default_fidelity: Optional[str] = None,
                 default_category: str = "Static Signature", cidr_expression: Optional[str] = None,
                 ocsf: Optional[Union[bool, str]] = None,
                 catalog_name: Optional[str] = None, schema_name: Optional[str] = None,
                 warehouse_id: Optional[str] = None, extend_lookback: Optional[str] = None,
                 **kwargs):
        """Initialize Databricks backend with optional Lakewatch, raw-log, CIDR and OCSF options."""
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self._raw_log_field_set = bool(raw_log_field)
        if raw_log_field:
            self.raw_log_field = raw_log_field
        # None: render OCSF array/free-form fields only for the lakewatch format or rules processed
        # by the OCSF pipeline; True/False force it on/off.
        self.ocsf = self._parse_bool_option("ocsf", ocsf)
        self._current_rule: Optional[SigmaRule] = None
        self._current_format: Optional[str] = None
        self._field_overrides: Dict[str, str] = {}
        if cidr_expression:
            self.cidr_expression = cidr_expression
        self.table_name = table_name
        self.lookback = lookback
        self.schedule = schedule
        self.compute_group = compute_group
        self.default_fidelity = default_fidelity
        self.default_category = default_category
        self.catalog_name = catalog_name
        self.schema_name = schema_name
        self.warehouse_id = warehouse_id
        self.extend_lookback = extend_lookback

    @staticmethod
    def _parse_bool_option(name: str, value: Optional[Union[bool, str]]) -> Optional[bool]:
        """Parse a tri-state backend option given as bool or string (as passed by sigma-cli)."""
        if value is None or isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in ("", "auto"):
            return None
        if normalized in ("true", "yes", "1"):
            return True
        if normalized in ("false", "no", "0"):
            return False
        raise ValueError(f"Invalid value for backend option {name}: {value!r} (expected true, false or auto)")

    def convert_rule(self, rule: SigmaRule, *args, **kwargs):
        """Convert a rule, remembering it and the output format to decide on OCSF field rendering."""
        output_format = args[0] if args else kwargs.get("output_format")
        self._current_rule = rule
        self._current_format = output_format or self.default_format
        return super().convert_rule(rule, *args, **kwargs)

    def _ocsf_enabled(self) -> bool:
        """Whether field names are OCSF attribute paths that need array/free-form aware rendering."""
        if self.ocsf is not None:
            return self.ocsf
        if self._current_format in ("lakewatch", "lakewatch_v2"):
            return True
        rule = self._current_rule
        return rule is not None and any(
            item_id.startswith("ocsf_") for item_id in getattr(rule, "applied_processing_items", ())
        )

    def _raw_field(self) -> str:
        """Field used for keyword searches: the explicit option, OCSF raw_data, or the default."""
        if not self._raw_log_field_set and self._ocsf_enabled():
            return self.ocsf_raw_log_field
        return self.raw_log_field

    def _ocsf_path(self, field: Optional[str]) -> Optional[OcsfPath]:
        if not field or not self._ocsf_enabled():
            return None
        return split_ocsf_path(field)

    @staticmethod
    def _struct_ref(base: Optional[str], segments: Tuple[str, ...]) -> str:
        """Dotted struct reference, backtick-quoting segments that aren't plain identifiers."""
        parts = [base] if base else []
        parts.extend(seg if re.fullmatch(r"\w+", seg) else "`" + seg.replace("`", "``") + "`"
                     for seg in segments)
        return ".".join(parts)

    @staticmethod
    def _json_path(keys: Tuple[str, ...]) -> str:
        """Databricks JSON path (as used after ':') for keys inside a VARIANT or JSON string column."""
        path = ""
        for i, key in enumerate(keys):
            if re.fullmatch(r"[A-Za-z_]\w*", key):
                path += key if i == 0 else "." + key
            else:
                path += "['" + key.replace("\\", "\\\\").replace("'", "\\'") + "']"
        return path

    @staticmethod
    def _json_cast(expr: str, value: Any) -> str:
        """Cast a free-form (VARIANT/JSON) value to the type the condition compares against."""
        if isinstance(value, (SigmaNumber, SigmaCompareExpression)):
            return f"try_cast({expr} AS DOUBLE)"
        if isinstance(value, SigmaBool):
            return f"try_cast({expr} AS BOOLEAN)"
        if isinstance(value, (SigmaNull, SigmaExists)):
            return expr
        return f"{expr}::string"

    def _render_ocsf_path(self, path: OcsfPath, value: Any) -> Tuple[List[Tuple[str, str]], str]:
        """Render an OCSF path as exists() levels (array, lambda variable) and the element expression."""
        levels: List[Tuple[str, str]] = []
        base: Optional[str] = None
        for depth, segments in enumerate(path.arrays):
            var = f"x{depth}"
            levels.append((self._struct_ref(base, segments), var))
            base = var
        leaf = self._struct_ref(base, path.leaf)
        if path.json_path:
            leaf = self._json_cast(f"{leaf}:{self._json_path(path.json_path)}", value)
        return levels, leaf

    @staticmethod
    def _wrap_exists(levels: List[Tuple[str, str]], expr: Any) -> Any:
        """Wrap an element-level expression into nested exists() over the OCSF arrays."""
        if not isinstance(expr, str):
            return expr
        for collection, var in reversed(levels):
            expr = f"exists({collection}, {var} -> {expr})"
        return expr

    def escape_and_quote_field(self, field_name: str) -> str:
        """Escape and quote a field name; element-level OCSF expressions are used as prepared."""
        override = self._field_overrides.get(field_name)
        if override is not None:
            return override
        return super().escape_and_quote_field(field_name)

    def convert_condition_field_eq_val(self, cond: ConditionFieldEqualsValueExpression,
                                       state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field = value conditions, rendering OCSF array and free-form fields."""
        path = self._ocsf_path(cond.field)
        if path is None or isinstance(cond.value, SigmaFieldReference):
            return super().convert_condition_field_eq_val(cond, state)
        levels, leaf = self._render_ocsf_path(path, cond.value)
        inner = copy.copy(cond)
        inner.field = self._ocsf_inner_field
        self._field_overrides[self._ocsf_inner_field] = leaf
        try:
            expr = super().convert_condition_field_eq_val(inner, state)
        finally:
            del self._field_overrides[self._ocsf_inner_field]
        return self._wrap_exists(levels, expr)

    def make_sql_string(self, s: SigmaString):
        """Convert a SigmaString to a quoted SQL string literal."""
        converted = s.convert(
            self.escape_char,
            None,
            None,
            (self.str_quote or "") + self.add_escaped,
            self.filter_chars,
        )
        return self.quote_string(converted)

    @staticmethod
    def sql_quote_regex(pattern: str) -> str:
        """Escape a regex for embedding into a single-quoted Spark SQL string literal (without quotes)."""
        return pattern.replace("\\", "\\\\").replace("'", "\\'")

    def convert_value_re(self, r: SigmaRegularExpression,
                         state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert a regex, adding Java's UNICODE_CASE flag so the i flag also applies to non-ASCII characters."""
        converted = super().convert_value_re(r, state)
        if self.re_flag_prefix and SigmaRegularExpressionFlag.IGNORECASE in r.flags and isinstance(converted, str):
            # The prefix generated by pySigma is "(?<flags>)"
            converted = converted.replace(")", "u)", 1)
        return converted

    def make_wildcard_regex(self, s: SigmaString) -> str:
        """Convert a SigmaString with wildcards into a quoted SQL string with an anchored regex.

        Literal parts are regex-escaped, wildcards become '.*' and '.'. The (?isu) flags make the
        match case-insensitive (also for non-ASCII characters, like lower()) and let wildcards span
        newlines; ^ and $ anchor it because rlike matches anywhere in the string.
        """
        parts: List[str] = []
        for part in s.s:
            if isinstance(part, str):
                parts.append(re.escape(part))
            elif part == SpecialChars.WILDCARD_MULTI:
                parts.append(".*")
            elif part == SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
            else:
                raise NotImplementedError(f"Unsupported part in wildcard string: {part!r}")
        return self.quote_string(self.sql_quote_regex("(?isu)^" + "".join(parts) + "$"))

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression,
                                           state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field = string value expressions."""
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
                value = self.make_wildcard_regex(sigma_value)
            else:  # We have just plain string
                expr = "lower({field}) = lower({value})"
                value = self.make_sql_string(sigma_value)

            return expr.format(field=self.escape_and_quote_field(cond.field),
                               value=value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            ) from None

    def convert_condition_val_str(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert unbound string values (keywords without field names)."""
        if not self._raw_field():
            raise ValueError("Unbound keyword search requires raw_log_field to be configured")

        # Use raw log field for keyword search
        field = self.escape_and_quote_field(self._raw_field())
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
            val_str = self.make_wildcard_regex(value)
            return self.wildcard_match_expression.format(field=field, value=val_str)
        else:
            # Plain keyword -> contains() (most common case)
            val_str = self.make_sql_string(value)
            if self.contains_expression:
                return self.contains_expression.format(field=field, value=val_str)
            raise ValueError("contains_expression is not defined")

    def convert_condition_val_re(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert unbound regex values."""
        if not self._raw_field():
            raise ValueError("Unbound regex search requires raw_log_field to be configured")

        # Type narrowing: ensure value is SigmaRegularExpression
        if not isinstance(cond.value, SigmaRegularExpression):
            raise TypeError(f"Expected SigmaRegularExpression, got {type(cond.value)}")

        field = self.escape_and_quote_field(self._raw_field())
        if self.re_expression:
            return self.re_expression.format(field=field, regex=self.convert_value_re(cond.value, state))
        raise ValueError("re_expression is not defined")

    def convert_condition_val_num(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert unbound numeric values."""
        if not self._raw_field():
            raise ValueError("Unbound numeric search requires raw_log_field to be configured")

        # Convert number to string search in raw log
        field = self.escape_and_quote_field(self._raw_field())
        value = self.make_sql_string(SigmaString(str(cond.value)))
        if self.contains_expression:
            return self.contains_expression.format(field=field, value=value)
        raise ValueError("contains_expression is not defined")

    def _analyze_or_for_regex_optimization(
        self, cond: ConditionOR
    ) -> Optional[Tuple[str, str, List[str]]]:
        """Analyze an OR condition to determine if it can be optimized as a regex expression.

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
                inner = value[1:-1]
            elif value.startswith(SpecialChars.WILDCARD_MULTI):
                # Endswith pattern: *value
                current_pattern = 'endswith'
                inner = value[1:]
            elif value.endswith(SpecialChars.WILDCARD_MULTI):
                # Startswith pattern: value*
                current_pattern = 'startswith'
                inner = value[:-1]
            else:
                # No wildcards, can't optimize as regex
                return None

            # Inner wildcards or placeholders can't be expressed as a literal alternative
            parts = [part for part in inner.s if isinstance(part, str)]
            if len(parts) != len(inner.s):
                return None
            actual_value = "".join(parts)

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
        """Build a case-insensitive regex pattern for the given pattern type and values.

        Uses (?iu) flags for case-insensitivity including non-ASCII characters (Java regex compatible).
        rlike matches anywhere in the string, so startswith/endswith patterns are anchored with ^ and $.
        """
        # Escape each value for use in regex (Java regex compatible)
        escaped_values = [re.escape(str(v)) for v in values]

        # Join values with pipe (OR in regex)
        alternatives = '|'.join(escaped_values)

        # Build pattern based on type
        if pattern_type == 'contains':
            pattern = f'(?iu).*({alternatives}).*'
        elif pattern_type == 'startswith':
            pattern = f'(?iu)^({alternatives})'
        elif pattern_type == 'endswith':
            pattern = f'(?iu)({alternatives})$'
        else:
            raise ValueError(f"Unknown pattern type: {pattern_type}")

        # The pattern is embedded into a SQL string literal
        return self.sql_quote_regex(pattern)

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions with optimization for repeated string matching patterns.

        If multiple OR conditions match the same field with the same pattern type
        (contains/startswith/endswith), they are optimized into a single regex expression.
        """
        # Try to optimize as regex
        optimization = self._analyze_or_for_regex_optimization(cond)

        if optimization:
            field_name, pattern_type, values = optimization

            # Build the optimized regex pattern
            regex_pattern = self._build_regex_pattern(pattern_type, values)

            # Use the re_expression format with escaped field name (or OCSF element expression)
            path = self._ocsf_path(field_name)
            levels: List[Tuple[str, str]] = []
            if path is None:
                field = self.escape_and_quote_field(field_name)
            else:
                levels, field = self._render_ocsf_path(path, SigmaString(""))
            if self.re_expression:
                return self._wrap_exists(levels, self.re_expression.format(field=field, regex=regex_pattern))
            raise ValueError("re_expression is not defined")

        # Fall back to default OR conversion
        return super().convert_condition_or(cond, state)

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def _lakewatch_table(self, rule: SigmaRule) -> str:
        """FROM table of a Lakewatch rule: the table_name option or the table of the OCSF class."""
        table = self.table_name or resolve_ocsf_table(rule)
        if not table:
            raise SigmaConversionError(
                f"Cannot determine Lakewatch table for rule '{rule.title}': no OCSF "
                "class_uid/type_uid/class_name present and no -O table_name given."
            )
        return table

    @staticmethod
    def _rule_status(rule: SigmaRule) -> str:
        return (rule.status.name if rule.status else "test").lower()

    @staticmethod
    def _lakewatch_severity(rule: SigmaRule) -> str:
        return SEVERITY_MAP.get(rule.level.name.lower(), "Medium") if rule.level else "Medium"

    def _lakewatch_fidelity(self, rule_status: str) -> str:
        return self.default_fidelity or FIDELITY_MAP.get(rule_status, "Development")

    def finalize_query_lakewatch(self, rule: SigmaRule, query: str, index: int,
                                 state: ConversionState) -> Any:
        """Build a Lakewatch v1 batch rule document for a single Sigma query."""
        table = self._lakewatch_table(rule)
        rule_status = self._rule_status(rule)
        sql = "" if not query.strip() else (
            f"SELECT *\nFROM {table}\n"
            f"WHERE time >= CURRENT_TIMESTAMP() - INTERVAL {self.lookback}\n"
            f"  AND ({query})"
        )
        spec_metadata: Dict[str, Any] = {
            "objective": rule.description or rule.title,
            "severity": self._lakewatch_severity(rule),
            "fidelity": self._lakewatch_fidelity(rule_status),
            "category": self.default_category,
        }
        mitre = build_mitre_mapping(rule)
        if mitre:
            spec_metadata["mitre"] = mitre
        doc: Dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "Rule",
            "metadata": {
                "displayName": rule.title,
                "comment": rule.description or rule.title,
            },
            "spec": {
                "input": {"batch": {"sql": sql}},
                "metadata": spec_metadata,
                "output": {"summary": rule.title, "defaultContext": True},
                "schedule": {
                    "atLeastEvery": self.schedule,
                    "computeGroup": self.compute_group,
                    "continuous": False,
                    "enabled": True,
                },
            },
        }
        return json.dumps({"status": rule_status, "sql": sql, "doc": doc})

    @staticmethod
    def _lakewatch_documents(queries: List[str]) -> List[Dict[str, Any]]:
        """Rule documents of the per-rule envelopes, without deprecated, unsupported and empty rules."""
        documents: List[Dict[str, Any]] = []
        for query in queries:
            envelope = json.loads(query)
            if envelope["status"] in ("deprecated", "unsupported") or not envelope["sql"]:
                continue
            documents.append(envelope["doc"])
        return documents

    @staticmethod
    def _dump_lakewatch_documents(documents: List[Dict[str, Any]]) -> str:
        """Render rule documents as one multi-document YAML file."""
        return "\n---\n".join(
            yaml.dump(
                doc,
                Dumper=_LakewatchDumper,
                sort_keys=False,
                default_flow_style=False,
                allow_unicode=True,
            )
            for doc in documents
        )

    def finalize_output_lakewatch(self, queries: List[str]) -> Any:
        """Assemble per-rule Lakewatch v1 documents into one multi-document YAML file."""
        return self._dump_lakewatch_documents(self._lakewatch_documents(queries))

    def finalize_query_lakewatch_v2(self, rule: SigmaRule, query: str, index: int,
                                    state: ConversionState) -> Any:
        """Build a Lakewatch v2 batch rule document for a single Sigma query."""
        catalog_name = (self.catalog_name or "").strip()
        schema_name = (self.schema_name or "").strip()
        if not catalog_name or not schema_name:
            raise SigmaConversionError(
                "Lakewatch v2 rules require the target Unity Catalog location: "
                "set the catalog_name and schema_name options (-O catalog_name=... -O schema_name=...)."
            )
        table = self._lakewatch_table(rule)
        rule_status = self._rule_status(rule)
        # The rule time window follows the schedule via IN_TIMERANGE(); use the
        # extend_lookback option to widen it.
        sql = "" if not query.strip() else (
            f"SELECT *\nFROM {table}\n"
            f"WHERE IN_TIMERANGE(time)\n"
            f"  AND ({query})"
        )
        doc: Dict[str, Any] = {
            "catalog_name": catalog_name,
            "schema_name": schema_name,
            "rule_name": to_v2_rule_name(rule.title),
            "description": rule.description or rule.title,
            "severity": self._lakewatch_severity(rule),
            "fidelity": to_v2_fidelity(self._lakewatch_fidelity(rule_status)),
            "category": self.default_category,
            "objective": rule.description or rule.title,
        }
        references = to_v2_references(rule.references)
        if references:
            doc["references"] = references
        doc["schedule"] = {
            "at_least_every": self.schedule,
            "compute_group": self.compute_group,
            "enabled": True,
        }
        if self.extend_lookback:
            doc["timerange"] = {"extend_lookback": self.extend_lookback}
        batch: Dict[str, Any] = {}
        if self.warehouse_id:
            batch["warehouse_id"] = self.warehouse_id
        # Unqualified table names resolve against the catalog and schema of the rule.
        batch["sql"] = {
            "query": sql,
            "default_catalog_name": catalog_name,
            "default_schema_name": schema_name,
        }
        doc["batch"] = batch
        doc["output"] = {"summary": rule.title, "default_context": True}
        mitre = to_v2_mitre(build_mitre_mapping(rule))
        if mitre:
            doc["mitre"] = mitre
        return json.dumps({"status": rule_status, "sql": sql, "doc": doc})

    def finalize_output_lakewatch_v2(self, queries: List[str]) -> Any:
        """Assemble per-rule Lakewatch v2 documents into one multi-document YAML file."""
        documents = self._lakewatch_documents(queries)
        # rule_name must be unique within the target schema: suffix duplicates.
        used = set()
        for doc in documents:
            name = candidate = doc["rule_name"]
            count = 1
            while candidate in used:
                count += 1
                suffix = f"_{count}"
                candidate = name[:V2_RULE_NAME_MAX_LEN - len(suffix)] + suffix
            used.add(candidate)
            doc["rule_name"] = candidate
        return self._dump_lakewatch_documents(documents)

    @staticmethod
    def finalize_query_dbsql(rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        """Finalize a DBSQL query by prepending rule metadata as a SQL comment."""
        rule_status = (rule.status.name if rule.status else "test").lower()
        title = rule.title.replace('\n', ' ')
        return f"-- title: \"{title}\". status: {rule_status}\n{query}"

    @staticmethod
    def finalize_output_dbsql(queries: List[str]) -> Any:
        """Join DBSQL queries with blank lines."""
        return "\n\n".join(queries)

    @staticmethod
    def finalize_query_detection_yaml(rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        """Serialize a rule query as a detection YAML record."""
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
        """Assemble detection YAML records into a single YAML document."""
        data: Dict[str, Any] = {"description": "Detections generated from Sigma rules"}
        detections: List[Any] = []
        for query in queries:
            d = json.loads(query)
            if d["status"] == "deprecated" or d["status"] == "unsupported" or d["sql"] == "":
                continue
            detections.append(d)
        data["detections"] = detections
        return yaml.dump(data, default_flow_style=False)
