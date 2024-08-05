from new_scans import validate_content

class RuleConditions:
    def __init__(self, raw_conditions: dict):
        self.data_type = raw_conditions['data_type']
        self.context = raw_conditions['context']
    
    def check_conditions(self, data: bytes, context: str):
        # detected_types = scan_sensitive_data(data)
        detected_types = validate_content(data.decode("utf-8"))

        # Check data 
        type_check = False
        if (self.data_type == 'all' and detected_types != []) or (self.data_type in detected_types):
            type_check = True

        # Check context (copy or paste)
        context_check = False
        if self.context == 'all' or self.context == context:
            context_check = True

        return type_check and context_check
