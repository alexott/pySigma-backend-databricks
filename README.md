# Setup
## Create a venv & activate it
```
python3.12 -m venv .venv
source .venv/bin/activate
```
## Update poetry dependencies
```
python3 -m pip install poetry
python3 -m poetry update
```

## Run testss
```
pytest
```

Status: **experimental**, work in progress:

* Although `cidrmatch` is generated, you still need to provide corresponding function as UDF (I'll add example later)
* Keywords (text rules without specific field) aren't supported yet
* Requires more testing

# pySigma Databricks Backend

This is the Databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.databricks`:

* `snake_case`: convert column names into snake case format

It supports the following output formats:

* default: plain Databricks/Apache Spark SQL queries
* dbsql: Databricks SQL queries with rules metadata (title, status) embedded as comment
* detection_yaml: Yaml markup for my own detection framework

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)
