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
