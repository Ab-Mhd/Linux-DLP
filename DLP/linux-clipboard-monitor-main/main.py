from x11_monitor import x11_monitor_main
from security import RuleHandler
from config import rule_file

RULE_HANDLER = None 

def main():
    global RULE_HANDLER

    print(f"Loading rule file {rule_file} (specified in config.py)")
    RULE_HANDLER = RuleHandler(rule_file)

    x11_monitor_main(RULE_HANDLER)


if __name__ == '__main__':
    main()
