
ACTION_PRIORITIES = {
    'alert': 0,
    'mask': 1,
    'quarantine': 2,
    'block': 3
}

def highest_priority_action():
    return max(ACTION_PRIORITIES, key=ACTION_PRIORITIES.get)

class RuleAction:
    def __init__(self, raw_action: dict):
        self.type = raw_action['type']
        self.message = raw_action['message'] if 'message' in raw_action else f"{self.type} event"
    
    # Returns the rule precedence, the higher the higher the precedence
    def priority(self) -> int:
        return ACTION_PRIORITIES[self.type]
    
    def compare_priority(self, action2):
        action2 if action2.priority() > self.priority() else self
    
    def get_audit_str(self):
        return f"{self.type} - {self.message}"


if __name__ == '__main__' :
    print(highest_priority_action())