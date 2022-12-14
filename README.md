![Tests](https://github.com/alexott/databricks-sigma-backend/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexott/GitHub Gist identifier containing coverage badge JSON expected by shields.io./raw/alexott-databricks-sigma-backend.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

Status: **experimental**, work in progress:

* Although `cidrmatch` is generated, you still need to provide corresponding function as UDF (I'll add example later)
* Keywords (text rules without specific field) aren't supported yet
* Requires more testing

# pySigma Databricks Backend

This is the Databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.databricks`:

* pipeline1: purpose
* pipeline2: purpose

It supports the following output formats:

* default: plain Databricks/Apacha Spark SQL queries
* detection_yaml: Yaml markup for my own small detection framework

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)


## TODOs

 - Try to rewrite expressions like `foo*bar` into `(startswith(field, "foo") and endswith(field, "bar"))`
 
