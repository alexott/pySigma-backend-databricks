"""Tests for the Databricks SQL backend."""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.databricks import DatabricksBackend


@pytest.fixture
def databricks_sigma_backend():
    return DatabricksBackend()


# TODO: implement tests for some basic queries and their expected results.
def test_databricks_sigma_and_expression(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["lower(fieldA) = 'valuea' AND lower(fieldB) = 'valueb'"]


def test_databricks_sigma_or_expression(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["lower(fieldA) = 'valuea' OR lower(fieldB) = 'valueb'"]


def test_databricks_sigma_match_with_dot_string(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value.A
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["lower(fieldA) = 'value.a' OR lower(fieldB) = 'valueb'"]


def test_databricks_sigma_and_or_expression(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["(lower(fieldA) IN ('valuea1', 'valuea2')) AND "
          "(lower(fieldB) IN ('valueb1', 'valueb2'))"]


def test_databricks_sigma_or_and_expression(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ["lower(fieldA) = 'valuea1' AND lower(fieldB) = 'valueb1' OR lower(fieldA) = 'valuea2' "
          "AND lower(fieldB) = 'valueb2'"]


def test_databricks_sigma_in_expression(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ["lower(fieldA) IN ('valuea', 'valueb') OR "
          "startswith(lower(fieldA), 'valuec')"]


def test_databricks_sigma_regex_query(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ["fieldA rlike 'foo.*bar' AND lower(fieldB) = 'foo'"]


def test_databricks_sigma_regex_query_flags(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re|i: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ["fieldA rlike '(?iu)foo.*bar' AND lower(fieldB) = 'foo'"]


def test_databricks_sigma_cidr_query(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["ip_cidr_contains('192.168.0.0/16', try_ip_as_binary(field))"]


def test_databricks_sigma_cidr_ipv6_query(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 2001:db8::/32
                condition: sel
        """)
    ) == ["ip_cidr_contains('2001:db8::/32', try_ip_as_binary(field))"]


def test_databricks_sigma_cidr_custom_expression():
    backend = DatabricksBackend(cidr_expression="cidrmatch({field}, '{value}')")
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr:
                        - 192.168.0.0/16
                        - 10.0.0.0/8
                condition: sel
        """)
    ) == ["cidrmatch(field, '192.168.0.0/16') OR cidrmatch(field, '10.0.0.0/8')"]
    # Override is per instance and doesn't leak into the class default
    assert DatabricksBackend.cidr_expression == "ip_cidr_contains('{value}', try_ip_as_binary({field}))"


def test_databricks_sigma_field_name_with_whitespace(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ["lower(`field name`) = 'value'"]


def test_databricks_sigma_field_name_with_period(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    responseElements.publiclyAccessible:
                        - value1
                condition: sel
        """)
    ) == ["lower(responseElements.publiclyAccessible) = 'value1'"]


def test_databricks_sigma_detection_yaml_output(databricks_sigma_backend: DatabricksBackend):
    sigma_rules = SigmaCollection.from_yaml("""
            title: Test
            status: stable
            logsource:
                category: test_category
                product: test_product
            level: high
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    queries = databricks_sigma_backend.convert(sigma_rules)
    final_queries = [databricks_sigma_backend.finalize_query_detection_yaml(q[0], q[1], 0, None)
                     for q in zip(sigma_rules.rules, queries)]
    yaml_rules = databricks_sigma_backend.finalize_output_detection_yaml(final_queries)
    assert yaml_rules == """description: Detections generated from Sigma rules
detections:
- name: Test
  severity: 50
  sql: fieldA rlike 'foo.*bar' AND lower(fieldB) = 'foo'
  status: release
  template: Test
"""


def test_databricks_sigma_dbsql_output(databricks_sigma_backend: DatabricksBackend):
    sigma_rules = SigmaCollection.from_yaml("""
            title: Test
            status: stable
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    queries = databricks_sigma_backend.convert(sigma_rules)
    final_queries = [databricks_sigma_backend.finalize_query_dbsql(q[0], q[1], 0, None)
                     for q in zip(sigma_rules.rules, queries)]
    sql_rules = databricks_sigma_backend.finalize_output_dbsql(final_queries)
    assert sql_rules == "-- title: \"Test\". status: stable\nfieldA rlike 'foo.*bar' AND lower(fieldB) = 'foo'"


def test_databricks_sigma_fieldref(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA: valueA
                filter:
                    fieldB|fieldref: fieldC
                condition: selection and not filter
        """)
    ) == ["lower(fieldA) = 'valuea' AND NOT fieldB = fieldC"]


def test_fieldref_contains_dbsql(databricks_sigma_backend: DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    a|fieldref|contains: b
                condition: selection
        """)
    ) == ["contains(lower(a), lower(b))"]


# Tests for OR optimization as regex (Issue #12)

def test_or_contains_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test optimization of OR conditions with contains into regex."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    CommandLine|contains:
                        - 'nessusd'
                        - 'santad'
                        - 'falcond'
                condition: selection
        """)
    ) == ["CommandLine rlike '(?iu).*(nessusd|santad|falcond).*'"]


def test_or_startswith_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test optimization of OR conditions with startswith into regex."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    UserAgent|startswith:
                        - 'XMRig '
                        - 'ccminer'
                        - 'ethminer'
                condition: selection
        """)
    ) == [r"UserAgent rlike '(?iu)^(XMRig\\ |ccminer|ethminer)'"]


def test_or_endswith_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test optimization of OR conditions with endswith into regex."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    Image|endswith:
                        - '/shutdown'
                        - '/reboot'
                        - '/halt'
                condition: selection
        """)
    ) == ["Image rlike '(?iu)(/shutdown|/reboot|/halt)$'"]


def test_or_with_special_regex_chars(databricks_sigma_backend: DatabricksBackend):
    """Test that special regex characters are properly escaped."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    FileName|contains:
                        - 'file.txt'
                        - 'test+'
                        - '[bracket]'
                condition: selection
        """)
    ) == [r"FileName rlike '(?iu).*(file\\.txt|test\\+|\\[bracket\\]).*'"]


def test_or_with_backslashes(databricks_sigma_backend: DatabricksBackend):
    """Test proper escaping of backslashes in regex patterns."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    Path|contains:
                        - 'C:\\Windows'
                        - 'D:\\Temp'
                        - 'E:\\Data'
                condition: selection
        """)
    ) == [r"Path rlike '(?iu).*(C:\\\\Windows|D:\\\\Temp|E:\\\\Data).*'"]


def test_or_with_pipes_and_parens(databricks_sigma_backend: DatabricksBackend):
    """Test proper escaping of pipes and parentheses."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    Value|contains:
                        - 'a|b'
                        - '(test)'
                        - 'c+d'
                condition: selection
        """)
    ) == [r"Value rlike '(?iu).*(a\\|b|\\(test\\)|c\\+d).*'"]


def test_or_mixed_patterns_no_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test that mixed pattern types (contains + startswith) are not optimized."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    field:
                        - 'value1*'
                        - '*value2'
                        - '*value3*'
                condition: selection
        """)
    )
    # Should fall back to individual function calls
    assert "startswith" in result[0]
    assert "endswith" in result[0]
    assert "contains" in result[0]
    assert "rlike" not in result[0]


def test_or_different_fields_no_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test that OR conditions on different fields are not optimized."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                sel1:
                    fieldA|contains: value1
                sel2:
                    fieldB|contains: value2
                sel3:
                    fieldC|contains: value3
                condition: 1 of sel*
        """)
    )
    # Should fall back to OR of contains expressions
    assert result[0].count("contains") == 3
    assert "rlike" not in result[0]


def test_or_below_threshold_no_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test that OR conditions below threshold (3 terms) are not optimized."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    field|contains:
                        - 'value1'
                        - 'value2'
                condition: selection
        """)
    )
    # Only 2 values, should not be optimized (threshold is 3)
    assert result[0].count("contains") == 2
    assert "rlike" not in result[0]


def test_complex_and_or_conditions(databricks_sigma_backend: DatabricksBackend):
    """Test that complex AND/OR conditions optimize each OR independently."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection1:
                    Image: '/usr/bin/grep'
                selection2:
                    CommandLine|contains:
                        - 'nessusd'
                        - 'santad'
                        - 'falcond'
                condition: selection1 and selection2
        """)
    )
    # Should have optimized the contains OR into regex
    assert "rlike '(?iu).*(nessusd|santad|falcond).*'" in result[0]
    assert "lower(Image) = '/usr/bin/grep'" in result[0]
    assert " AND " in result[0]


def test_optimization_disabled(databricks_sigma_backend: DatabricksBackend):
    """Test that optimization can be disabled via configuration."""
    # Temporarily disable optimization
    original_value = databricks_sigma_backend.optimize_or_as_regex
    databricks_sigma_backend.optimize_or_as_regex = False

    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    field|contains:
                        - 'value1'
                        - 'value2'
                        - 'value3'
                condition: selection
        """)
    )

    # Restore original value
    databricks_sigma_backend.optimize_or_as_regex = original_value

    # Should use contains functions instead of regex
    assert result[0].count("contains") == 3
    assert "rlike" not in result[0]


def test_real_sigma_rule_macos_security(databricks_sigma_backend: DatabricksBackend):
    """Test with real Sigma rule from issue #12 Example 1."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Security Software Discovery - MacOs
            status: test
            logsource:
                product: macos
                category: process_creation
            detection:
                image:
                    Image: '/usr/bin/grep'
                selection_cli_1:
                    CommandLine|contains:
                        - 'nessusd'
                        - 'santad'
                        - 'CbDefense'
                        - 'falcond'
                        - 'td-agent'
                        - 'packetbeat'
                        - 'filebeat'
                        - 'auditbeat'
                        - 'osqueryd'
                        - 'BlockBlock'
                        - 'LuLu'
                condition: image and selection_cli_1
        """)
    )
    # Should optimize the 11 contains into a single regex
    expected_regex = (
        r"rlike '(?iu).*(nessusd|santad|CbDefense|falcond|td\\-agent|"
        "packetbeat|filebeat|auditbeat|osqueryd|BlockBlock|LuLu).*'"
    )
    assert expected_regex in result[0]
    # Should not have individual contains calls
    assert "contains(" not in result[0]
    # Should have the AND condition with Image check
    assert "lower(Image) = '/usr/bin/grep'" in result[0]


def test_databricks_sigma_no_status(databricks_sigma_backend: DatabricksBackend):
    sigma_rules = SigmaCollection.from_yaml("""
            title: Test Without Status
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: sel
        """)
    queries = databricks_sigma_backend.convert(sigma_rules)
    # Test that finalize_query_detection_yaml handles None status
    final_query = databricks_sigma_backend.finalize_query_detection_yaml(
        sigma_rules.rules[0], queries[0], 0, None
    )
    assert '"status": "test"' in final_query
    # Test that finalize_query_dbsql handles None status
    final_query_dbsql = databricks_sigma_backend.finalize_query_dbsql(
        sigma_rules.rules[0], queries[0], 0, None
    )
    assert "status: test" in final_query_dbsql


# Tests for unbound keyword search
def test_databricks_sigma_unbound_keywords_or(databricks_sigma_backend: DatabricksBackend):
    """Test unbound keywords with default OR logic."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Unbound Keywords OR
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 'keyword1'
                    - 'keyword2'
                condition: keywords
        """)
    ) == ["contains(lower(raw), 'keyword1') OR contains(lower(raw), 'keyword2')"]


def test_databricks_sigma_unbound_keywords_all(databricks_sigma_backend: DatabricksBackend):
    """Test unbound keywords with |all modifier (AND logic)."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Unbound Keywords AND
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    '|all':
                        - 'Remove-MailboxExportRequest'
                        - ' -Identity '
                        - ' -Confirm "False"'
                condition: keywords
        """)
    ) == ['contains(lower(raw), \'remove-mailboxexportrequest\') AND ' +
          'contains(lower(raw), \' -identity \') AND ' +
          'contains(lower(raw), \' -confirm "false"\')']


def test_databricks_sigma_mixed_field_and_keywords(databricks_sigma_backend: DatabricksBackend):
    """Test mixing field-based conditions with unbound keywords."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Mixed Conditions
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    EventID: 4688
                keywords:
                    - 'evil'
                condition: selection and keywords
        """)
    ) == ["EventID = 4688 AND contains(lower(raw), 'evil')"]


def test_databricks_sigma_custom_raw_field():
    """Test using custom raw log field name."""
    backend = DatabricksBackend(raw_log_field="message")
    result = backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Custom Field
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 'test'
                condition: keywords
        """)
    )
    assert "message" in result[0]
    assert "contains(lower(message), 'test')" in result[0]


def test_databricks_sigma_unbound_regex(databricks_sigma_backend: DatabricksBackend):
    """Test unbound regex patterns."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Unbound Regex
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - '|re': '.*evil(cmd|powershell).*'
                condition: keywords
        """)
    )
    assert "raw rlike '.*evil(cmd|powershell).*'" in result[0]


def test_databricks_sigma_unbound_wildcards(databricks_sigma_backend: DatabricksBackend):
    """Test wildcards in unbound keywords."""
    # Test contains pattern (*keyword*)
    result1 = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
            detection:
                keywords:
                    - '*evil*'
                condition: keywords
        """)
    )
    assert "contains(lower(raw), 'evil')" in result1[0]

    # Test startswith pattern (keyword*)
    result2 = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
            detection:
                keywords:
                    - 'cmd.exe*'
                condition: keywords
        """)
    )
    assert "startswith(lower(raw), 'cmd.exe')" in result2[0]

    # Test endswith pattern (*keyword)
    result3 = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
            detection:
                keywords:
                    - '*.exe'
                condition: keywords
        """)
    )
    assert "endswith(lower(raw), '.exe')" in result3[0]


def test_databricks_sigma_unbound_numeric(databricks_sigma_backend: DatabricksBackend):
    """Test unbound numeric values."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Unbound Numeric
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 12345
                condition: keywords
        """)
    )
    assert "contains(lower(raw), '12345')" in result[0]


def test_databricks_sigma_unbound_complex_condition(databricks_sigma_backend: DatabricksBackend):
    """Test complex conditions with multiple keyword groups."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Complex
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords1:
                    '|all':
                        - 'mimikatz'
                        - 'sekurlsa'
                keywords2:
                    - 'password'
                    - 'credential'
                selection:
                    EventID: 4688
                condition: selection and (keywords1 or keywords2)
        """)
    )
    # Verify it contains all the expected parts
    assert "EventID" in result[0]
    assert "mimikatz" in result[0]
    assert "sekurlsa" in result[0]
    assert "password" in result[0]
    assert "credential" in result[0]


def test_or_optimization_sql_escaping(databricks_sigma_backend: DatabricksBackend):
    """Test that the merged regex is escaped for the SQL string literal (backslashes and quotes)."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    CommandLine|contains:
                        - 'dig +short TXT'
                        - "o'brien"
                        - 'nslookup'
                condition: selection
        """)
    ) == [r"CommandLine rlike '(?iu).*(dig\\ \\+short\\ TXT|o\'brien|nslookup).*'"]


def test_or_inner_wildcard_no_optimization(databricks_sigma_backend: DatabricksBackend):
    """Test that values with inner wildcards are not merged into a regex as literal characters."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test
                product: test
            detection:
                selection:
                    CommandLine|contains:
                        - 'a*b'
                        - 'c'
                        - 'd'
                condition: selection
        """)
    ) == ["CommandLine rlike '(?isu)^.*a.*b.*$' OR contains(lower(CommandLine), 'c') OR "
          "contains(lower(CommandLine), 'd')"]


def test_databricks_sigma_regex_query_sql_escaping(databricks_sigma_backend: DatabricksBackend):
    """Test that regex values are escaped for the SQL string literal."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 'dig \+short ''x'''
                condition: sel
        """)
    ) == [r"fieldA rlike 'dig \\+short \'x\''"]


def test_databricks_sigma_unbound_regex_sql_escaping(databricks_sigma_backend: DatabricksBackend):
    """Test that unbound regex values are escaped for the SQL string literal."""
    result = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - '|re': '\d+ ''x'''
                condition: keywords
        """)
    )
    assert result == [r"raw rlike '\\d+ \'x\''"]


def test_databricks_sigma_exists(databricks_sigma_backend: DatabricksBackend):
    """Test the exists modifier."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|exists: true
                    fieldB|exists: false
                condition: sel
        """)
    ) == ["fieldA is not null AND fieldB is null"]


def test_databricks_sigma_wildcard_regex(databricks_sigma_backend: DatabricksBackend):
    """Test that inner wildcards produce an anchored regex with escaped literal parts."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: 'C:\Win*a+b?.exe'
                    CommandLine: "*o'brien*x*"
                condition: sel
        """)
    ) == [r"Image rlike '(?isu)^C:\\\\Win.*a\\+b.\\.exe$' AND CommandLine rlike '(?isu)^.*o\'brien.*x.*$'"]


def test_databricks_sigma_unbound_wildcard_regex(databricks_sigma_backend: DatabricksBackend):
    """Test that unbound keywords with inner wildcards produce an anchored regex."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 'evil*cmd.exe'
                condition: keywords
        """)
    ) == [r"raw rlike '(?isu)^evil.*cmd\\.exe$'"]


def test_databricks_sigma_unicode_case_insensitive(databricks_sigma_backend: DatabricksBackend):
    """Test that case-insensitive regexes enable Java's UNICODE_CASE flag."""
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|re|i|m: 'привет'
                    fieldB|re: 'ПРИВЕТ'
                sel2:
                    fieldC|contains:
                        - 'привет'
                        - 'мир'
                        - 'ä'
                condition: sel1 or sel2
        """)
    ) == ["fieldA rlike '(?imu)привет' AND fieldB rlike 'ПРИВЕТ' OR "
          "fieldC rlike '(?iu).*(привет|мир|ä).*'"]


def _convert_sel(backend: DatabricksBackend, sel: str) -> str:
    return backend.convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
{sel}
                condition: sel
        """)
    )[0]


def test_ascii_literal_lowercased(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    Image: 'C:\\Windows\\CMD.exe'")
    assert out == r"lower(Image) = 'c:\\windows\\cmd.exe'"


def test_non_ascii_literal_keeps_lower(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    User: 'İnsan'")
    assert out == "lower(User) = lower('İnsan')"


@pytest.mark.parametrize("mod,fn", [("contains", "contains"), ("startswith", "startswith"), ("endswith", "endswith")])
def test_contains_startswith_endswith_ascii(databricks_sigma_backend: DatabricksBackend, mod, fn):
    out = _convert_sel(databricks_sigma_backend, f"                    CommandLine|{mod}: 'ABC'")
    assert out == f"{fn}(lower(CommandLine), 'abc')"


def test_keyword_ascii_and_non_ascii(databricks_sigma_backend: DatabricksBackend):
    out = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 'EVIL'
                    - 'Ünïcode'
                condition: keywords
        """)
    )[0]
    assert out == "contains(lower(raw), 'evil') OR contains(lower(raw), lower('Ünïcode'))"


def test_or_eq_strings_become_in(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    Image: [a.exe, b.exe]")
    assert out == "lower(Image) IN ('a.exe', 'b.exe')"


def test_or_eq_numbers_stay_or_chain_in_plain_format(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    EventID: [1, 5]")
    assert out == "EventID = 1 OR EventID = 5"


def test_or_single_value_no_in(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    Image: a.exe")
    assert out == "lower(Image) = 'a.exe'"


def test_or_mixed_atoms_and_wildcards(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    Image: [a.exe, b.exe, '*\\c.exe', d.exe]")
    assert out == r"lower(Image) IN ('a.exe', 'b.exe', 'd.exe') OR endswith(lower(Image), '\\c.exe')"


def test_or_duplicates_kept(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    Image: [a, a]")
    assert out == "lower(Image) IN ('a', 'a')"


def test_or_non_ascii_element(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    Image: [a, 'İ']")
    assert out == "lower(Image) IN ('a', lower('İ'))"


def test_not_over_in(databricks_sigma_backend: DatabricksBackend):
    out = databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: [a.exe, b.exe]
                condition: not sel
        """)
    )[0]
    assert out == "NOT (lower(Image) IN ('a.exe', 'b.exe'))"


def test_or_cidr_list_exists(databricks_sigma_backend: DatabricksBackend):
    out = _convert_sel(databricks_sigma_backend, "                    src_ip|cidr: [10.0.0.0/8, 192.168.0.0/16]")
    assert out == ("exists(array('10.0.0.0/8', '192.168.0.0/16'), "
                   "cidr0 -> ip_cidr_contains(cidr0, try_ip_as_binary(src_ip)))")


def test_or_cidr_custom_expression_no_merge():
    backend = DatabricksBackend(cidr_expression="cidrmatch({field}, '{value}')")
    out = _convert_sel(backend, "                    src_ip|cidr: [10.0.0.0/8, 192.168.0.0/16]")
    assert out == "cidrmatch(src_ip, '10.0.0.0/8') OR cidrmatch(src_ip, '192.168.0.0/16')"
