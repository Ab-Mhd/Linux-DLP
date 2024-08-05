from typing import List
from .rule_conditions import RuleConditions
from .rule_actions import RuleAction
from .rule_exceptions import RuleExceptions

class DLPRule:
    def __init__(self, raw_rule: dict):
        self.id = raw_rule['rule_id']
        self.description = raw_rule['description']
        # self.priority = raw_rule['priority']  # Don't think we'll use this 
        self.enabled = raw_rule['enabled']
        self.conditions = RuleConditions(raw_rule['conditions'])
        self.actions = [RuleAction(raw_action) for raw_action in raw_rule['actions']]
        self.exceptions = RuleExceptions(raw_rule['exceptions'])
    
    def check_rule(self, data: bytes, context: str, application_name: str, application_user: str) -> List[RuleAction]:
        # Check conditions
        condition_check = self.conditions.check_conditions(data, context)
        # Check exceptions
        exception_check = False 
        if application_name or application_user:
            exception_check = self.exceptions.check_exceptions(application_name, application_user)
        # Return actions
        return self.actions if condition_check and not exception_check else []

    def __str__(self) -> str:
        return f"""Rule {self.id}:
Description: {self.description}
Enabled: {self.enabled}
Conditions: {self.conditions}
Actions: {self.actions}
Conditions: {self.exceptions}
"""