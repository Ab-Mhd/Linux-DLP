class RuleExceptions:
    def __init__(self, raw_exception: dict):
        self.whitelist_applications = raw_exception['whitelist_applications']
        self.whitelist_users = raw_exception['whitelist_users']
    
    def check_exceptions(self, application_name: str, application_user: str):
        # Check application name
        # Check application user
        should_be_exception = application_name in self.whitelist_applications or application_user in self.whitelist_users
        return should_be_exception