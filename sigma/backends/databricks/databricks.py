"""Databricks/Apache Spark SQL backend for pySigma, including Lakewatch output format."""

import copy
import dataclasses
import json
import re
import warnings
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Dict,
    FrozenSet,
    List,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
    Type,
    Union,
)

import yaml
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionItem, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaConfigurationError, SigmaConversionError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaDetection, SigmaLevel, SigmaRule
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

from .field_paths import FieldPath, UnknownFieldError, resolve_schema_path, split_join_field_name
from .json_text import json_escape_string, looks_like_json
from .lakewatch_maps import (
    FIDELITY_MAP,
    SEVERITY_MAP,
    V2_DESCRIPTION_MAX_LEN,
    V2_FIDELITY_MAP,
    V2_OBJECTIVE_MAX_LEN,
    V2_RULE_NAME_MAX_LEN,
    build_mitre_mapping,
    build_v2_annotations,
    build_v2_runbook,
    resolve_ocsf_table,
    to_v2_fidelity,
    to_v2_mitre,
    to_v2_references,
    to_v2_rule_name,
    truncate,
)
from .ocsf_fields import split_ocsf_path
from .schema_catalog import ParserSchema, SchemaCatalog

if TYPE_CHECKING:  # pragma: no cover
    # Imported lazily at runtime: the profile module imports this package (import cycle).
    from sigma.pipelines.databricks.lakewatch.profile import Profile, RawSource


# Type of a Windows EventData-style VARIANT: a list of {_Name, _VALUE} elements.
_NAMED_ENTRY_TYPE = "ARRAY<STRUCT<_Name: STRING, _VALUE: STRING>>"
_NAMED_OBJECT_TYPE = "STRUCT<_Name: STRING, _VALUE: STRING>"

class LakewatchConversionError(SigmaConversionError):
    """Conversion error of the Lakewatch v2 parsed-table mode.

    Constructed with pySigma's ``SigmaConversionError(rule, source, message)`` signature, but
    rendered as ``<reason> (rule '<title>', <location>)``: the base class appends the
    ``repr()`` of the whole rule. The location is omitted if the rule has no source.
    """

    def __init__(self, rule: Optional[SigmaRule], reason: str):
        """Create the error for ``rule`` (its source is used as the location)."""
        super().__init__(rule, getattr(rule, "source", None), reason)  # type: ignore[arg-type]
        self.reason = reason

    def __str__(self) -> str:
        """Return the reason followed by the rule title and location, when known."""
        details = []
        title = getattr(self.rule, "title", None)
        if title:
            details.append(f"rule '{title}'")
        if self.source is not None:
            details.append(str(self.source))
        return f"{self.reason} ({', '.join(details)})" if details else self.reason


class _LakewatchDumper(yaml.SafeDumper):
    """YAML dumper that renders multi-line strings as literal block scalars."""


def _represent_str_block(dumper: yaml.SafeDumper, data: str):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_LakewatchDumper.add_representer(str, _represent_str_block)


def _collect_field_values(detection: Any, field: str, found: List[Set[str]]) -> None:
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            _collect_field_values(item, field, found)
        elif item.field == field:
            values: Set[str] = set()
            for v in item.value:
                if isinstance(v, SigmaString):
                    values.add("*" if v.contains_special() else str(v).lower())
                elif isinstance(v, SigmaNumber):
                    values.add(str(v).lower())
                else:
                    values.add("*")
            found.append(values)


def rule_field_values(rule: SigmaRule, field: str) -> Optional[Set[str]]:
    """Lower-cased values of all detection items named ``field``; ``*`` marks a wildcard or odd value.

    Returns None when no detection item names the field.
    """
    found: List[Set[str]] = []
    for detection in rule.detection.detections.values():
        _collect_field_values(detection, field, found)
    if not found:
        return None
    return set().union(*found)


def _routes(profile: "Profile", schema: ParserSchema, block: Any, rule: SigmaRule) -> bool:
    """Whether the rule is routed to this profile block by its route field's values."""
    route = block.route
    if route is None:
        return True
    values = rule_field_values(rule, route.field)
    if values is None or "*" in values:
        return True
    include = route.include
    if include is None and not route.exclude:
        include = frozenset()
        for mapping_target in profile.mappings_for(block)[route.field].targets:
            info = schema.get(mapping_target)
            if info is None or info.allowed is None:
                return True
            include |= frozenset(a.lower() for a in info.allowed)
    if include is not None:
        return any(v in include for v in values)
    return any(v not in route.exclude for v in values)


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
    field_equals_field_startswith_expression: ClassVar[Optional[str]] = "startswith(lower({field1}), lower({field2}))"
    field_equals_field_endswith_expression: ClassVar[Optional[str]] = "endswith(lower({field1}), lower({field2}))"
    field_equals_field_contains_expression: ClassVar[Optional[str]] = "contains(lower({field1}), lower({field2}))"

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
                 enabled: Optional[Union[bool, str]] = None,
                 parsers: Optional[Union[str, Sequence[str]]] = None,
                 lakewatch_profiles_dir: Optional[Union[str, Sequence[str]]] = None,
                 lakewatch_schemas: Optional[Union[str, Sequence[str]]] = None,
                 table_map: Optional[Union[str, Sequence[str]]] = None,
                 output_dir: Optional[str] = None,
                 **kwargs):
        """Initialize Databricks backend with optional Lakewatch, raw-log, CIDR and OCSF options.

        Lakewatch v2 parsed-table options (comma-separated strings, as passed by sigma-cli):
        ``parsers`` (profile ids to convert for), ``lakewatch_profiles_dir`` (extra profile
        directories), ``lakewatch_schemas`` (extra parser schema files) and ``table_map``
        (``profile:table`` pairs).

        ``output_dir`` makes ``lakewatch_v2`` write one ``<rule_name>.yaml`` file per rule into
        that directory instead of returning a multi-document YAML file.
        """
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
        # Lakewatch v2 rules are emitted disabled unless enabled=true: review before scheduling.
        self.enabled = bool(self._parse_bool_option("enabled", enabled))
        self.parsers = self._split_list_option(parsers)
        self.lakewatch_profiles_dir = self._split_list_option(lakewatch_profiles_dir)
        self.lakewatch_schemas = self._split_list_option(lakewatch_schemas)
        self.table_map = self._split_list_option(table_map)
        self.output_dir = (output_dir or "").strip() or None
        # Parsed-table mode state: the selected (profile, schema, table) triples, set up lazily
        # on the first parsed-mode rule, and the one the current rule is converted for.
        self._selected: Optional[List[Tuple["Profile", ParserSchema, str]]] = None
        self._current_profile: Optional[Tuple["Profile", ParserSchema, str]] = None
        # Targets of the current profile block's mappings with ``undeclared: true``.
        self._current_undeclared: FrozenSet[str] = frozenset()
        # Raw event source of the current profile (keyword searches) and whether the approximate
        # warning was already issued for the current rule and profile.
        self._current_raw: Optional["RawSource"] = None
        self._raw_warned = False

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
        """Convert a rule, remembering it and the output format to decide on OCSF field rendering.

        In Lakewatch v2 parsed-table mode the rule is converted once per selected parser
        profile that matches its logsource (see ``_convert_rule_parsed``).
        """
        output_format = args[0] if args else kwargs.get("output_format")
        self._current_rule = rule
        self._current_format = output_format or self.default_format
        if self._parsed_mode(self._current_format):
            return self._convert_rule_parsed(rule, self._current_format, args, kwargs)
        return super().convert_rule(rule, *args, **kwargs)

    def _ocsf_enabled(self) -> bool:
        """Whether field names are OCSF attribute paths that need array/free-form aware rendering."""
        if self.ocsf is not None:
            return self.ocsf
        if self._current_format == "lakewatch":
            return True
        if self._current_format == "lakewatch_v2":
            return not self._parsed_mode(self._current_format)
        rule = self._current_rule
        return rule is not None and any(
            item_id.startswith("ocsf_") for item_id in getattr(rule, "applied_processing_items", ())
        )

    def _raw_field(self) -> str:
        """Field used for keyword searches: the explicit option, OCSF raw_data, or the default."""
        if not self._raw_log_field_set and self._ocsf_enabled():
            return self.ocsf_raw_log_field
        return self.raw_log_field

    def _raw_expression(self) -> Tuple[str, "RawSource"]:
        """Return the SQL expression of the raw event text keywords search in, and its source.

        Outside parsed-table mode this is the escaped raw log field (text). In parsed mode it is
        the profile's raw source, or the ``raw_log_field`` option when given.
        """
        from sigma.pipelines.databricks.lakewatch.profile import RawSource

        if self._current_profile is None:
            name = self._raw_field()
            return self.escape_and_quote_field(name), RawSource("column", name, "text")
        profile, schema, _ = self._current_profile
        raw = self._current_raw
        if raw is None:
            raise self._parsed_error(f"no raw event for keyword search in profile {profile.profile}")
        if raw.kind == "column":
            path = resolve_schema_path(schema, raw.value)
            return self._render_path(path, SigmaString(""))[1], raw
        if raw.kind == "entries":
            path = resolve_schema_path(schema, f"{raw.value}[x]")
            entries = self._named_entries(path)
            return f"array_join(transform({entries}, e -> e._VALUE), '\\n')", raw
        return f"({raw.value})", raw

    def _warn_raw(self, raw: "RawSource") -> None:
        """Warn once per rule and profile that the keyword search is approximate."""
        if self._current_profile is None or not raw.approximate or self._raw_warned:
            return
        self._raw_warned = True
        self._warn(f"keyword search over the {raw.kind} source of profile "
                   f"{self._current_profile[0].profile} is approximate")

    def _warn(self, message: str) -> None:
        """Issue a UserWarning naming the current rule and, in parsed mode, the profile."""
        rule = self._current_rule
        title = rule.title if rule is not None else "?"
        pid = f" (profile {self._current_profile[0].profile})" if self._current_profile else ""
        warnings.warn(f"rule '{title}'{pid}: {message}", UserWarning, stacklevel=2)

    def _field_path(self, field: Optional[str]) -> Optional[FieldPath]:
        """Path of a field that needs backend rendering, or None to render it as a plain name.

        In parsed-table mode every field is resolved against the current profile's parser
        schema; otherwise OCSF paths with arrays or free-form attributes are split.
        """
        if not field:
            return None
        if self._current_profile is not None:
            if field in self._field_overrides:
                # An expression rendered already (an inner placeholder): use it as it is.
                return None
            return self._resolve_parsed_field(field)
        if not self._ocsf_enabled():
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

    def _render_path(self, path: FieldPath, value: Any,
                     as_type: Optional[str] = None) -> Tuple[List[Tuple[str, str]], str]:
        """Render a field path as exists() levels (array, lambda variable) and the element expression.

        ``as_type`` forces the type of a VARIANT key extraction (parsed-table mode).

        VARIANT keys are extracted with try_variant_get() in parsed-table mode and with the
        ``col:path`` syntax plus a cast in OCSF mode. A named entry ``Field[Name]`` is the
        ``_VALUE`` of the first ``{_Name, _VALUE}`` element with that name.
        """
        if path.entry is not None:
            return [], self._named_entry(path)
        if path.first:
            return [], self._first_set(path)
        if path.join:
            # Scalar parts (no arrays), each extracted as a string; an empty part is skipped.
            parts = ", ".join(f"nullif({self._join_part(part)}, '')" for part in path.join)
            return [], f"concat_ws('{self.sql_quote_regex(path.join_sep)}', {parts})"
        levels: List[Tuple[str, str]] = []
        base: Optional[str] = None
        for depth, segments in enumerate(path.arrays):
            var = f"x{depth}"
            levels.append((self._struct_ref(base, segments), var))
            base = var
        leaf = self._struct_ref(base, path.leaf)
        if path.json_path:
            if self._current_profile is not None:
                leaf = self._variant_get(leaf, path, value, as_type)
            else:
                leaf = self._json_cast(f"{leaf}:{self._json_path(path.json_path)}", value)
        return levels, leaf

    def _first_set(self, path: FieldPath) -> str:
        """Render the first set of the candidates as CASE WHEN; NULL and '' are always unset."""
        unset = ", ".join(
            f"'{self.sql_quote_regex(u)}'" for u in dict.fromkeys([*path.first_unset, ""])
        )
        branches = []
        for candidate in path.first[:-1]:
            key = candidate.join[-1] if candidate.join else candidate
            branches.append(
                f"WHEN coalesce({self._join_part(key)}, '') NOT IN ({unset}) "
                f"THEN {self._candidate_expr(candidate)}"
            )
        return f"CASE {' '.join(branches)} ELSE {self._candidate_expr(path.first[-1])} END"

    def _candidate_expr(self, candidate: FieldPath) -> str:
        return self._render_path(candidate, SigmaString(""))[1] if candidate.join else self._join_part(candidate)

    def _join_part(self, part: FieldPath) -> str:
        """Return the string expression of a scalar join part, whatever its declared type."""
        if part.json_path:
            # A VARIANT key is always extracted as a string, also when declared with another type.
            return self._render_path(dataclasses.replace(part, json_type=None), SigmaString(""))[1]
        expr = self._render_path(part, SigmaString(""))[1]
        return expr if part.leaf_type == "STRING" else f"cast({expr} AS STRING)"

    def _named_entries(self, path: FieldPath) -> str:
        """Return the ``ARRAY<STRUCT<_Name, _VALUE>>`` expression of a named-entry path.

        A VARIANT is read as the list, or as a single ``{_Name, _VALUE}`` object (the one-element
        form); an ARRAY<STRUCT> column is the list itself.
        """
        source = self._struct_ref(None, path.leaf)
        if not path.entry_variant:
            return source
        return (
            f"coalesce(try_variant_get({source}, '$', '{_NAMED_ENTRY_TYPE}'), "
            f"CASE WHEN try_variant_get({source}, '$._Name', 'STRING') IS NOT NULL THEN "
            f"array(try_variant_get({source}, '$', '{_NAMED_OBJECT_TYPE}')) END)"
        )

    def _named_entry(self, path: FieldPath) -> str:
        """Value of a named entry of a ``{_Name, _VALUE}`` list (VARIANT or ARRAY<STRUCT>).

        The entry ``*`` is the unnamed ``Data`` of a VARIANT: all plain strings joined with newlines.
        """
        if path.entry == "*":
            source = self._struct_ref(None, path.leaf)
            return (
                f"array_join(coalesce(try_variant_get({source}, '$', 'ARRAY<STRING>'), "
                f"CASE WHEN schema_of_variant({source}) = 'STRING' THEN "
                f"array(try_variant_get({source}, '$', 'STRING')) END), '\\n')"
            )
        name = self.sql_quote_regex(path.entry or "")
        return f"try_element_at(filter({self._named_entries(path)}, e -> e._Name = '{name}'), 1)._VALUE"

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
        """Convert field = value conditions, rendering array, STRUCT and VARIANT/free-form fields."""
        path = self._field_path(cond.field)
        if path is not None and self._current_profile is not None:
            if isinstance(cond.value, SigmaFieldReference):
                self._check_parsed_field_reference(path, cond.value)
                return super().convert_condition_field_eq_val(cond, state)
            self._check_parsed_struct(path, cond.field, cond.value)
            self._warn_parsed_allowed(path, cond)
            cond = self._coerce_parsed_value(path, cond)
        if path is None or isinstance(cond.value, SigmaFieldReference):
            return super().convert_condition_field_eq_val(cond, state)
        if (
            self._current_profile is not None
            and self._is_variant_object(path)
            and isinstance(cond.value, SigmaString)
        ):
            cond, levels, leaf = self._variant_json_text(path, cond)
        else:
            levels, leaf = self._render_path(path, cond.value)
        if (
            self._current_profile is not None
            and isinstance(cond.value, SigmaCompareExpression)
            and (path.json_type or path.leaf_type) == "STRING"
        ):
            # Ordering comparisons on STRING values: compare numerically, NULL if not a number.
            leaf = f"try_cast({leaf} AS DOUBLE)"
        inner = copy.copy(cond)
        inner.field = self._ocsf_inner_field
        self._field_overrides[self._ocsf_inner_field] = leaf
        try:
            expr = super().convert_condition_field_eq_val(inner, state)
        finally:
            del self._field_overrides[self._ocsf_inner_field]
        return self._wrap_exists(levels, expr)

    def convert_condition_field_eq_val_cidr(self, cond: ConditionFieldEqualsValueExpression,
                                            state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert CIDR matches, substituting a prepared element-level expression for the field.

        pySigma formats cidr_expression with the raw field name instead of escape_and_quote_field().
        """
        override = self._field_overrides.get(cond.field) if cond.field else None
        if override is not None:
            cond = copy.copy(cond)
            cond.field = override
        return super().convert_condition_field_eq_val_cidr(cond, state)

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
        field, raw = self._raw_expression()
        value = cond.value

        # Type narrowing: ensure value is SigmaString
        if not isinstance(value, SigmaString):
            raise TypeError(f"Expected SigmaString, got {type(value)}")
        self._warn_raw(raw)
        if raw.encoding == "json" and self._current_profile is not None:
            if looks_like_json(value):
                self._warn("keyword looks like a JSON fragment")
            value = json_escape_string(value)

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

        field, raw = self._raw_expression()
        self._warn_raw(raw)
        if raw.encoding == "json" and self._current_profile is not None:
            self._warn("regex keyword is not JSON-escaped")
        if self.re_expression:
            return self.re_expression.format(field=field, regex=self.convert_value_re(cond.value, state))
        raise ValueError("re_expression is not defined")

    def convert_condition_val_num(self, cond, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert unbound numeric values."""
        if not self._raw_field():
            raise ValueError("Unbound numeric search requires raw_log_field to be configured")

        # Convert number to string search in raw log
        field, raw = self._raw_expression()
        self._warn_raw(raw)
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

        if self._current_profile is not None:
            field_path = self._field_path(field_name)
            if field_path is not None and self._is_variant_object(field_path):
                return None  # Matched over the JSON text of the VARIANT, with escaping

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

            # Use the re_expression format with escaped field name (or rendered element expression)
            path = self._field_path(field_name)
            levels: List[Tuple[str, str]] = []
            if path is None:
                field = self.escape_and_quote_field(field_name)
            else:
                if self._current_profile is not None:
                    self._check_parsed_struct(path, field_name, SigmaString(""))
                levels, field = self._render_path(path, SigmaString(""))
            if self.re_expression:
                return self._wrap_exists(levels, self.re_expression.format(field=field, regex=regex_pattern))
            raise ValueError("re_expression is not defined")

        # Fall back to default OR conversion
        return super().convert_condition_or(cond, state)

    # --- Lakewatch v2 parsed-table mode ---------------------------------------------------
    # Rules are converted against the output tables of Lakewatch parsers. Each selected mapping
    # profile (-O parsers=...) that matches the rule's logsource gets its own copy of the rule,
    # processed by the user pipeline followed by the profile pipeline, and fields are rendered
    # from the parser schema (STRUCT dot access, try_variant_get() for VARIANT keys, exists()
    # over arrays).

    def _parsed_error(self, message: str) -> SigmaConversionError:
        """Conversion error for the current rule; ``str()`` starts with ``message``."""
        return LakewatchConversionError(self._current_rule, message)

    @staticmethod
    def _split_list_option(value: Optional[Union[str, Sequence[str]]]) -> List[str]:
        """Split a comma-separated option (or a list of them), stripping blanks and empty items."""
        if value is None:
            return []
        items = [value] if isinstance(value, str) else list(value)
        return [part.strip() for item in items for part in str(item).split(",") if part.strip()]

    def _ocsf_pipeline_selected(self) -> bool:
        """Whether the processing pipeline contains OCSF items (identifier prefix ``ocsf_``)."""
        pipeline = self.processing_pipeline
        return pipeline is not None and any(
            (item.identifier or "").startswith("ocsf_") for item in pipeline.items
        )

    def _parsed_mode(self, output_format: Optional[str]) -> bool:
        """Whether rules are converted for Lakewatch parser tables (the lakewatch_v2 default).

        OCSF mode is used instead with ``-O ocsf=true`` or a pipeline with ``ocsf_`` items.
        ``-O parsers`` with any other format, or together with OCSF mode, is an error.
        """
        if output_format != "lakewatch_v2":
            if self.parsers:
                raise SigmaConfigurationError(
                    f"-O parsers=... is only supported by the lakewatch_v2 format, not {output_format}"
                )
            return False
        if self.ocsf is True or self._ocsf_pipeline_selected():
            if self.parsers:
                raise SigmaConfigurationError(
                    "-O parsers=... selects Lakewatch parsed tables and cannot be combined with "
                    "OCSF mode (-O ocsf=true or an ocsf_ processing pipeline)"
                )
            return False
        return True

    def _parse_table_map(self) -> Dict[str, str]:
        """Parse ``table_map`` items (``profile:table``, split on the first ':')."""
        tables: Dict[str, str] = {}
        for item in self.table_map:
            pid, sep, table = (part.strip() for part in item.partition(":"))
            if not sep or not pid or not table:
                raise SigmaConfigurationError(
                    f"malformed -O table_map entry '{item}': expected <profile>:<table>"
                )
            if pid in tables:
                raise SigmaConfigurationError(f"duplicate -O table_map entry for profile {pid}")
            tables[pid] = table
        return tables

    def _parsed_setup(self) -> None:
        """Load schemas and profiles and resolve the selected profiles and their tables (once).

        Raises SigmaConfigurationError for missing or unknown parsers, invalid profiles and
        missing or ambiguous tables. Stores ``self._selected`` in ``-O parsers`` order.
        """
        if self._selected is not None:
            return
        from sigma.pipelines.databricks.lakewatch.profile import (
            RawSource,
            _validate_raw,
            load_profiles,
            validate_profile,
        )

        if not (self.catalog_name or "").strip() or not (self.schema_name or "").strip():
            raise SigmaConfigurationError(
                "Lakewatch v2 rules require the target Unity Catalog location: "
                "set the catalog_name and schema_name options (-O catalog_name=... -O schema_name=...)."
            )

        catalog = SchemaCatalog.load(self.lakewatch_schemas)
        profiles = load_profiles(self.lakewatch_profiles_dir)
        available = ", ".join(sorted(profiles))
        if not self.parsers:
            raise SigmaConfigurationError(
                f"-O parsers=... is required for lakewatch_v2 parsed tables; available: {available}"
            )
        duplicates = sorted({pid for pid in self.parsers if self.parsers.count(pid) > 1})
        if duplicates:
            raise SigmaConfigurationError(
                f"duplicate Lakewatch parser profiles in -O parsers: {', '.join(duplicates)}"
            )
        unknown = [pid for pid in self.parsers if pid not in profiles]
        if unknown:
            raise SigmaConfigurationError(
                f"unknown Lakewatch parser profiles in -O parsers: {', '.join(unknown)}; "
                f"available: {available}"
            )
        tables = self._parse_table_map()
        unselected = [pid for pid in tables if pid not in self.parsers]
        if unselected:
            raise SigmaConfigurationError(
                f"-O table_map names profiles that are not selected in -O parsers: {', '.join(unselected)}"
            )
        table_name = (self.table_name or "").strip()
        if table_name and len(self.parsers) > 1:
            raise SigmaConfigurationError(
                "-O table_name can only be used with exactly one parser; "
                "use -O table_map=<profile>:<table>,... for several parsers"
            )
        selected: List[Tuple["Profile", ParserSchema, str]] = []
        missing: List[str] = []
        for pid in self.parsers:
            profile = profiles[pid]
            schema = catalog.get(profile.parser)
            validate_profile(profile, schema)
            if self._raw_log_field_set:
                _validate_raw(profile, schema, RawSource("column", self.raw_log_field, "text"))
            table = tables.get(pid) or table_name
            if not table:
                missing.append(pid)
                continue
            selected.append((profile, schema, table))
        if missing:
            raise SigmaConfigurationError(
                f"no table for Lakewatch parser profiles {', '.join(missing)}: set "
                "-O table_map=<profile>:<table>,... (or -O table_name=... with exactly one parser)"
            )
        self._selected = selected

    def _convert_rule_parsed(self, rule: SigmaRule, output_format: str,
                             args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> List[Any]:
        """Convert a rule once per selected profile matching its logsource, concatenating results."""
        self._parsed_setup()
        assert self._selected is not None
        matches = [
            (profile, schema, table, block)
            for profile, schema, table in self._selected
            if (block := profile.block_for(rule.logsource)) is not None
        ]
        logsource_matches = matches
        matches = [m for m in matches if _routes(m[0], m[1], m[3], rule)]
        if logsource_matches and not matches:
            route = next(m[3].route for m in logsource_matches if m[3].route is not None)
            values = sorted(rule_field_values(rule, route.field) or ())
            error = self._parsed_error(
                f"no selected Lakewatch parser profile accepts {route.field} values {values} "
                f"of this rule; matching the logsource: "
                f"{', '.join(m[0].profile for m in logsource_matches)}"
            )
            if self.collect_errors:
                self.errors.append((rule, error))
                return []
            raise error
        if not matches:
            ls = rule.logsource
            error = self._parsed_error(
                f"no selected Lakewatch parser profile matches logsource "
                f"{ls.product}/{ls.category}/{ls.service}; "
                f"selected: {', '.join(p.profile for p, _, _ in self._selected)}"
            )
            if self.collect_errors:
                self.errors.append((rule, error))
                return []
            raise error
        # Restore the pipeline set up by convert() (needed by finalize()); None otherwise, so
        # that conversions to other formats initialize their pipeline normally.
        previous: Any = getattr(self, "last_processing_pipeline", None)
        results: List[Any] = []
        try:
            for profile, schema, table, block in matches:
                results.extend(self._convert_one_profile(
                    rule, output_format, (profile, schema, table), block, args, kwargs))
        finally:
            self.last_processing_pipeline = previous
            self._current_profile = None
            self._current_raw = None
            self._current_undeclared = frozenset()
            self._current_rule = rule
        return results

    def _convert_one_profile(self, rule: SigmaRule, output_format: str,
                             selected: Tuple["Profile", ParserSchema, str], block: Any,
                             args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> List[Any]:
        """Convert a copy of the rule with the user pipeline followed by the profile pipeline."""
        from sigma.pipelines.databricks.lakewatch import build_profile_pipeline
        from sigma.pipelines.databricks.lakewatch.profile import RawSource

        pipeline = (
            self.backend_processing_pipeline
            + (self.processing_pipeline if self.processing_pipeline is not None else ProcessingPipeline())
            + self.output_format_processing_pipeline[output_format]
            + build_profile_pipeline(selected[0], block, rule.logsource,
                                     keywords=True if self._raw_log_field_set else None)
        )
        # Same variables as Backend.init_processing_pipeline().
        pipeline.vars.update({"backend_" + key: value for key, value in self.backend_options.items()})
        pipeline.vars["backend"] = self.name
        pipeline.vars["output_format"] = output_format
        self.last_processing_pipeline = pipeline
        self._current_profile = selected
        self._current_raw = (
            RawSource("column", self.raw_log_field, "text") if self._raw_log_field_set else selected[0].raw
        )
        self._raw_warned = False
        self._current_undeclared = frozenset(
            target
            for mapping in selected[0].mappings_for(block).values() if mapping.undeclared
            for target in mapping.targets
        )
        rule_copy = copy.deepcopy(rule)
        self._current_rule = rule_copy
        first_error = len(self.errors)
        try:
            return super().convert_rule(rule_copy, *args, **kwargs)
        except LakewatchConversionError as error:
            if error.rule is rule_copy:
                error.rule = rule
            raise
        finally:
            # Report collected errors against the rule that was passed in, not its copy.
            self.errors[first_error:] = [
                (rule if failed is rule_copy else failed, error)
                for failed, error in self.errors[first_error:]
            ]
            for _, collected in self.errors[first_error:]:
                if isinstance(collected, LakewatchConversionError) and collected.rule is rule_copy:
                    collected.rule = rule

    def _resolve_parsed_field(self, field: str) -> FieldPath:
        """Resolve a field against the current profile's parser schema, failing closed.

        Keys not declared under a VARIANT are accepted only for targets of ``undeclared: true``
        mappings, also for each part of a join field.
        """
        assert self._current_profile is not None
        profile, schema, _ = self._current_profile
        try:
            allow_undeclared = field in self._current_undeclared
            join = split_join_field_name(field)
            if join is not None:
                allow_undeclared = False
                for part in join[1]:
                    try:
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            resolve_schema_path(schema, part)
                    except UnknownFieldError:
                        if part not in self._current_undeclared:
                            raise
                        allow_undeclared = True
            path = resolve_schema_path(schema, field, allow_undeclared)
        except UnknownFieldError as e:
            raise self._parsed_error(f"{e} (profile {profile.profile})") from None
        return path

    @staticmethod
    def _is_variant_object(path: FieldPath) -> bool:
        """Whether a path is a whole VARIANT column or a VARIANT/STRUCT key declared inside one."""
        return path.whole_variant or bool(path.json_path and path.json_type in ("VARIANT", "STRUCT"))

    @staticmethod
    def _is_contains_value(value: Any) -> bool:
        """Whether a value is a string with a leading and a trailing ``*`` (a contains match)."""
        return (
            isinstance(value, SigmaString)
            and value.startswith(SpecialChars.WILDCARD_MULTI)
            and value.endswith(SpecialChars.WILDCARD_MULTI)
        )

    def _check_parsed_struct(self, path: FieldPath, field: str, value: Any) -> None:
        """Fail on comparisons against a whole STRUCT or a whole VARIANT, except contains.

        A STRUCT column or member (also the element of ARRAY<STRUCT>) can't be compared. A whole
        VARIANT column, or a VARIANT/STRUCT key declared inside one, accepts only a contains match
        (over its JSON text). Null and exists checks remain valid SQL and are allowed.
        """
        assert self._current_profile is not None
        if isinstance(value, (SigmaNull, SigmaExists)):
            return
        if self._is_variant_object(path):
            if self._is_contains_value(value):
                return
            raise self._parsed_error(
                f"comparison against the whole VARIANT column {field} supports only contains "
                f"(profile {self._current_profile[0].profile})"
            )
        if path.json_path or path.leaf_type != "STRUCT":
            return
        raise self._parsed_error(
            f"comparison against the whole STRUCT field {field} is not supported "
            f"(profile {self._current_profile[0].profile})"
        )

    def _variant_json_text(
        self, path: FieldPath, cond: ConditionFieldEqualsValueExpression
    ) -> Tuple[ConditionFieldEqualsValueExpression, List[Tuple[str, str]], str]:
        """Prepare a contains match over the JSON text of a VARIANT: to_json() and an escaped value."""
        assert isinstance(cond.value, SigmaString)
        levels, leaf = self._render_path(path, cond.value, as_type="variant")
        title = getattr(self._current_rule, "title", None)
        warnings.warn(
            f"rule '{title}': {cond.field} is matched against the JSON text of a VARIANT (approximate)",
            UserWarning,
            stacklevel=2,
        )
        escaped = copy.copy(cond)
        escaped.value = json_escape_string(cond.value)
        return escaped, levels, f"to_json({leaf})"

    def _check_parsed_field_reference(self, path: FieldPath, ref: SigmaFieldReference) -> None:
        """Field references may use plain columns, STRUCT members, VARIANT keys and named entries."""
        assert self._current_profile is not None
        ref_path = self._resolve_parsed_field(ref.field)
        if path.join or ref_path.join or path.first or ref_path.first:
            raise self._parsed_error(
                "field references to joined fields are not supported "
                f"(profile {self._current_profile[0].profile})"
            )
        if any(p.arrays or p.whole_variant or (p.leaf_type == "STRUCT" and not p.json_path) for p in (path, ref_path)):
            raise self._parsed_error(
                "field references to nested ARRAY/VARIANT fields are not supported "
                f"(profile {self._current_profile[0].profile})"
            )

    def convert_condition_field_eq_field_escape_and_quote(self, field1: str, field2: str) -> Tuple[str, str]:
        """Render both fields of a field reference from the parser schema in parsed-table mode."""
        if self._current_profile is None:
            return super().convert_condition_field_eq_field_escape_and_quote(field1, field2)
        return (
            self._render_path(self._resolve_parsed_field(field1), SigmaString(""))[1],
            self._render_path(self._resolve_parsed_field(field2), SigmaString(""))[1],
        )

    def _warn_parsed_allowed(self, path: FieldPath, cond: ConditionFieldEqualsValueExpression) -> None:
        """Warn when a plain string or number can never match the field's declared values."""
        assert self._current_profile is not None
        value = cond.value
        if path.allowed is None or not (
            isinstance(value, SigmaNumber)
            or (isinstance(value, SigmaString) and not value.contains_special())
        ):
            return
        if str(value).lower() in {a.lower() for a in path.allowed}:
            return
        title = getattr(self._current_rule, "title", None)
        warnings.warn(
            f"rule '{title}': {cond.field} = '{value}' never matches parser "
            f"{self._current_profile[0].parser}; allowed: {list(path.allowed)}",
            UserWarning,
            stacklevel=2,
        )

    @staticmethod
    def _coerce_parsed_value(path: FieldPath, cond: ConditionFieldEqualsValueExpression
                             ) -> ConditionFieldEqualsValueExpression:
        """Compare numbers and booleans against STRING fields as string literals (on a copy)."""
        value = cond.value
        if (path.json_type or path.leaf_type) != "STRING" or not isinstance(value, (SigmaNumber, SigmaBool)):
            return cond
        coerced = copy.copy(cond)
        if isinstance(value, SigmaBool):
            coerced.value = SigmaString("true" if value.boolean else "false")
        else:
            coerced.value = SigmaString(str(value))
        return coerced

    def _variant_get(self, expr: str, path: FieldPath, value: Any, as_type: Optional[str] = None) -> str:
        """try_variant_get() of a key inside a VARIANT, typed by the schema or the compared value."""
        json_path = self._json_path(path.json_path)
        json_path = ("$" if json_path.startswith("[") else "$.") + json_path
        if as_type:
            type_name = as_type
        elif path.json_type and path.json_type not in ("VARIANT", "STRUCT"):
            type_name = path.json_type.lower()
        elif isinstance(value, (SigmaNumber, SigmaCompareExpression)):
            type_name = "double"
        elif isinstance(value, SigmaBool):
            type_name = "boolean"
        else:
            type_name = "string"
        return f"try_variant_get({expr}, '{self.sql_quote_regex(json_path)}', '{type_name}')"

    # --- end of Lakewatch v2 parsed-table mode ---------------------------------------------

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def _lakewatch_table(self, rule: SigmaRule) -> str:
        """FROM table of a Lakewatch rule.

        The parsed-mode profile table, the table_name option or the table of the OCSF class.
        """
        if self._current_profile is not None:
            return self._current_profile[2]
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

    def _lakewatch_v2_fidelity(self, rule_status: str) -> str:
        return to_v2_fidelity(self.default_fidelity or V2_FIDELITY_MAP.get(rule_status, "Development"))

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
        rule_name_suffix = ""
        profile_ref: Optional[str] = None
        if self._current_profile is not None:
            current = self._current_profile[0]
            rule_name_suffix = f"__{current.profile}"
            profile_ref = f"{current.profile}@{current.version}"
        rule_status = self._rule_status(rule)
        # The rule time window follows the schedule via IN_TIMERANGE(); use the
        # extend_lookback option to widen it.
        sql = "" if not query.strip() else (
            f"SELECT *\nFROM {table}\n"
            f"WHERE IN_TIMERANGE(time)\n"
            f"  AND ({query})"
        )
        description = rule.description or rule.title
        doc: Dict[str, Any] = {
            "catalog_name": catalog_name,
            "schema_name": schema_name,
            "rule_name": to_v2_rule_name(rule.title, rule_name_suffix),
            "description": truncate(description, V2_DESCRIPTION_MAX_LEN),
            "severity": self._lakewatch_severity(rule),
            "fidelity": self._lakewatch_v2_fidelity(rule_status),
            "category": self.default_category,
            "objective": truncate(description, V2_OBJECTIVE_MAX_LEN),
        }
        references = to_v2_references(rule.references)
        if references:
            doc["references"] = references
        runbook = build_v2_runbook(rule)
        if runbook:
            doc["runbook"] = runbook
        annotations = build_v2_annotations(rule, profile_ref)
        if annotations:
            doc["annotations"] = annotations
        # schedule.compute_group was removed from the v2 API (rules run on dedicated compute).
        doc["schedule"] = {
            "at_least_every": self.schedule,
            "enabled": self.enabled,
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
        doc["output"] = {
            "summary": rule.title,
            "event_time_column": "time",
            "default_context": True,
        }
        mitre = to_v2_mitre(build_mitre_mapping(rule))
        if mitre:
            doc["mitre"] = mitre
        return json.dumps({"status": rule_status, "sql": sql, "doc": doc})

    def finalize_output_lakewatch_v2(self, queries: List[str]) -> Any:
        """Assemble per-rule Lakewatch v2 documents into one multi-document YAML file."""
        documents = self._lakewatch_documents(queries)
        if documents:
            self._warn_lakewatch_v2_options()
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
        if self.output_dir:
            return self._write_lakewatch_v2_files(documents, self.output_dir)
        return self._dump_lakewatch_documents(documents)

    @classmethod
    def _write_lakewatch_v2_files(cls, documents: List[Dict[str, Any]], output_dir: str) -> str:
        """Write each document to ``<output_dir>/<rule_name>.yaml`` and return a summary comment.

        Rule names are unique and contain only ``[a-z0-9_]``, so they are safe file names.
        Existing files with the same name are overwritten; other files are left alone.
        """
        directory = Path(output_dir).expanduser()
        try:
            directory.mkdir(parents=True, exist_ok=True)
            for doc in documents:
                (directory / f"{doc['rule_name']}.yaml").write_text(
                    cls._dump_lakewatch_documents([doc]), encoding="utf-8")
        except OSError as e:
            raise SigmaConfigurationError(f"cannot write rules to output_dir {directory}: {e}") from None
        return f"# Wrote {len(documents)} Lakewatch v2 rule(s) to {directory}"

    def finalize(self, queries: List[Any], output_format: str) -> Any:
        """Finalize the output, warning when ``output_dir`` is set for a format that ignores it."""
        if self.output_dir and output_format != "lakewatch_v2":
            warnings.warn(
                f"The output_dir option is supported only by the lakewatch_v2 format and is "
                f"ignored for {output_format}.",
                UserWarning, stacklevel=2,
            )
        return super().finalize(queries, output_format)

    def _warn_lakewatch_v2_options(self) -> None:
        """Warn once per conversion about options that make the v2 rules fail or are ignored."""
        if not self.warehouse_id:
            warnings.warn(
                "Lakewatch v2 rules have no warehouse_id: the server rejects enabled batch rules "
                "without one (RULE_BATCH_PYSPARK_DISABLED). Set -O warehouse_id=...",
                UserWarning, stacklevel=2,
            )
        if self.compute_group != "automatic":
            warnings.warn(
                "The compute_group option is ignored for Lakewatch v2: schedule.compute_group was "
                "removed from the v2 API.",
                UserWarning, stacklevel=2,
            )

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
