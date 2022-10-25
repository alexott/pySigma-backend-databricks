from sigma.backends.databricks.SigmaLinkParser import *


def test_sigma_parse_directory():
    link = "https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws"
    for rule in parse_sigma_link(link):
        print(rule.title)


def test_sigma_parse_link():
    link = "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_cloudtrail_disable_logging.yml"
    for rule in parse_sigma_link(link):
        print(rule.title)


def test_sigma_parse_raw_link():
    link = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/cloud/aws/aws_cloudtrail_disable_logging.yml"
    for rule in parse_sigma_link(link):
        print(rule.title)
