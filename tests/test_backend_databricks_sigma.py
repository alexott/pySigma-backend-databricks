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
    ) == ["lower(fieldA) = lower('valueA') AND lower(fieldB) = lower('valueB')"]


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
    ) == ["lower(fieldA) = lower('valueA') OR lower(fieldB) = lower('valueB')"]


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
    ) == ["lower(fieldA) = lower('value.A') OR lower(fieldB) = lower('valueB')"]


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
    ) == ["(lower(fieldA) = lower('valueA1') OR lower(fieldA) = lower('valueA2')) AND "
          "(lower(fieldB) = lower('valueB1') OR lower(fieldB) = lower('valueB2'))"]


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
    ) == ["lower(fieldA) = lower('valueA1') AND lower(fieldB) = lower('valueB1') OR lower(fieldA) = lower('valueA2') "
          "AND lower(fieldB) = lower('valueB2')"]


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
    ) == ["lower(fieldA) = lower('valueA') OR lower(fieldA) = lower('valueB') OR "
          "startswith(lower(fieldA), lower('valueC'))"]


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
    ) == ["fieldA rlike 'foo.*bar' AND lower(fieldB) = lower('foo')"]


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
    ) == ["fieldA rlike '(?i)foo.*bar' AND lower(fieldB) = lower('foo')"]


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
    ) == ["cidrmatch(field, '192.168.0.0/16')"]


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
    ) == ["lower(`field name`) = lower('value')"]


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
    ) == ["lower(responseElements.publiclyAccessible) = lower('value1')"]


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
  sql: fieldA rlike 'foo.*bar' AND lower(fieldB) = lower('foo')
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
    assert sql_rules == "-- title: \"Test\". status: stable\nfieldA rlike 'foo.*bar' AND lower(fieldB) = lower('foo')"


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
    ) == ["lower(fieldA) = lower('valueA') AND NOT fieldB = fieldC"]


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
    ) == ["CommandLine rlike '(?i).*(nessusd|santad|falcond).*'"]


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
    ) == ["UserAgent rlike '(?i)(XMRig\\ |ccminer|ethminer).*'"]


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
    ) == ["Image rlike '(?i).*(/shutdown|/reboot|/halt)'"]


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
    ) == ["FileName rlike '(?i).*(file\\.txt|test\\+|\\[bracket\\]).*'"]


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
    ) == ["Path rlike '(?i).*(C:\\\\Windows|D:\\\\Temp|E:\\\\Data).*'"]


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
    ) == ["Value rlike '(?i).*(a\\|b|\\(test\\)|c\\+d).*'"]


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
    assert "rlike '(?i).*(nessusd|santad|falcond).*'" in result[0]
    assert "lower(Image) = lower('/usr/bin/grep')" in result[0]
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
    assert "rlike '(?i).*(nessusd|santad|CbDefense|falcond|td\\-agent|packetbeat|filebeat|auditbeat|osqueryd|BlockBlock|LuLu).*'" in result[0]
    # Should not have individual contains calls
    assert "contains(" not in result[0]
    # Should have the AND condition with Image check
    assert "lower(Image) = lower('/usr/bin/grep')" in result[0]


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
    """Test unbound keywords with default OR logic"""
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
    ) == ["contains(lower(raw), lower('keyword1')) OR contains(lower(raw), lower('keyword2'))"]


def test_databricks_sigma_unbound_keywords_all(databricks_sigma_backend: DatabricksBackend):
    """Test unbound keywords with |all modifier (AND logic)"""
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
    ) == ['contains(lower(raw), lower(\'Remove-MailboxExportRequest\')) AND ' +
          'contains(lower(raw), lower(\' -Identity \')) AND ' +
          'contains(lower(raw), lower(\' -Confirm "False"\'))']


def test_databricks_sigma_mixed_field_and_keywords(databricks_sigma_backend: DatabricksBackend):
    """Test mixing field-based conditions with unbound keywords"""
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
    ) == ["EventID = 4688 AND contains(lower(raw), lower('evil'))"]


def test_databricks_sigma_custom_raw_field():
    """Test using custom raw log field name"""
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
    assert "contains(lower(message), lower('test'))" in result[0]


def test_databricks_sigma_unbound_regex(databricks_sigma_backend: DatabricksBackend):
    """Test unbound regex patterns"""
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
    """Test wildcards in unbound keywords"""
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
    assert "contains(lower(raw), lower('evil'))" in result1[0]
    
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
    assert "startswith(lower(raw), lower('cmd.exe'))" in result2[0]
    
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
    assert "endswith(lower(raw), lower('.exe'))" in result3[0]


def test_databricks_sigma_unbound_numeric(databricks_sigma_backend: DatabricksBackend):
    """Test unbound numeric values"""
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
    assert "contains(lower(raw), lower('12345'))" in result[0]


def test_databricks_sigma_unbound_complex_condition(databricks_sigma_backend: DatabricksBackend):
    """Test complex conditions with multiple keyword groups"""
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
