from datetime import datetime
import json
from typing import List 
from Rules.dlp_rule import DLPRule
from Rules.rule_actions import RuleAction, highest_priority_action
import config
from Sensitive_Scans import tags

class RuleHandler:
    def __init__(self, rule_file: str):
        self.rules = load_rules(rule_file)

    def handle_event(self, clipboard_data, context, application_name, application_user):
        # There needs to be some kind of priority for rules as well as their
        # actions, e.g. a block action is always more significant than an audit.
        # A primitive rule priority can be implemented using their original
        # order.

        # Find first matching rule, and get its actions
        for rule in self.rules:
            resulting_actions = rule.check_rule(clipboard_data, context, application_name, application_user)
            if resulting_actions != []:
                break
            
        # Return the signals so the clipboard monitor can respond accordingly 
        action_signals = []
        for action in resulting_actions:
            action_signals.append(action.type)
            self.audit(action.get_audit_str())
        
        return action_signals


    def audit(self, message):
        with open(config.audit_file, 'a') as f:
           f.write(f'[{datetime.now()}] {message}.\n')
        print(f'[{datetime.now()}] {message}.\n')

def load_rules(rule_file):
    with open(rule_file, 'r') as f:
        raw_rules = json.loads(f.read())
    
    rules = []
    for rule in raw_rules['rules']:
        rules.append(DLPRule(rule))
    return rules

def quarantine(clipdata):
    with open(config.quarantine_file, 'a') as qfile:
        qfile.write(f"Quarantined data: {clipdata}\n")

def mask_data(data: bytes):
    mask_char = "X"
    sensitive_parts = [(t[1], t[2]) for t in tags(data.decode("utf-8"))]
    sdata = data.decode("utf-8")
    for part in sensitive_parts:
        start, length = part
        sdata = sdata[:start] + mask_char*length + sdata[start+length:]
    return sdata.encode("utf-8")


if __name__ == '__main__':
    rule_handler = RuleHandler("./ExampleRules/example_rules2.json")
    print(rule_handler.handle_event(b"TESTING TESTING *SENSITIVE*"))
    #print(handle_copy(b"TESTING TESTING *SENSITIVE*"))
