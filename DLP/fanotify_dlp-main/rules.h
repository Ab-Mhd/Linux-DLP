//
// Created by user on 7/22/24.
//

#ifndef FANOTIFY_RULES_H
#define FANOTIFY_RULES_H

// Structure Definitions
typedef struct {
    char *pathRegex;
    char *destinationType;
    char *fileExtension;

    char **allowedApplications;
    int allowedApplicationsCount;
    int isSensitiveFile;
    char *sensitiveDataType;
} Conditions;

typedef struct {
    char *name;
    int priority;
    char *operationType;
    char *action;
    Conditions conditions;
} Rule;

typedef struct {
    Rule *dlpRules;
    int dlpRulesCount;
    Rule *dcRules;
    int dcRulesCount;
} Rules;

typedef enum {
    IGNORE = 0,
    LOG,
    BLOCK
} RuleAction;

// Function Definitions

Rule parseRule(cJSON *ruleJson);
Rules parseRules(const char *json);
void freeRules(Rules *rules);
char *readFromFile(char *filename);
Rules loadRulesFromFile(char *filename);
int isRulesNull(Rules rules);
void printRules(Rules rules);
int checkRuleConditions(Rule* rule, const char* filePath, const char* executablePath);

#endif //FANOTIFY_RULES_H
