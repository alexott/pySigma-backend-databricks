from sigma.rule import SigmaRuleTag
from sigma.backends.databricks import DatabricksBackend
from sigma.collection import SigmaCollection


class SigmaRule:
    def __init__(self, rule):
        from_yaml = SigmaCollection.from_yaml(rule)
        self.filter_expr = DatabricksBackend().convert(from_yaml)[0]
        self.original_object = from_yaml.rules[0]
        self.fields = {}

        for key, val in vars(self.original_object).items():
            self.fields[key] = val
