from db_sigma.backends.databricks.SigmaLinkParser import *


def test_databricks_sigma_and_expression():
    link = "https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws"
    for rule in parse_sigma_directory(link):
        print(rule.title)
