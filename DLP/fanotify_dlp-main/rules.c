//
// Created by user on 7/22/24.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <cjson/cJSON.h>
#include "rules.h"
#include "sensitive.h"

// Updated function to parse a single rule
Rule parseRule(cJSON *ruleJson) {
    Rule rule = {0};

    cJSON *name = cJSON_GetObjectItemCaseSensitive(ruleJson, "name");
    cJSON *priority = cJSON_GetObjectItemCaseSensitive(ruleJson, "priority");
    cJSON *operationType = cJSON_GetObjectItemCaseSensitive(ruleJson, "operationType");
    cJSON *action = cJSON_GetObjectItemCaseSensitive(ruleJson, "action");
    cJSON *conditions = cJSON_GetObjectItemCaseSensitive(ruleJson, "conditions");

    if (cJSON_IsString(name) && name->valuestring != NULL) {
        rule.name = strdup(name->valuestring);
    }
    if (cJSON_IsNumber(priority)) {
        rule.priority = priority->valueint;
    }
    if (cJSON_IsString(operationType) && operationType->valuestring != NULL) {
        rule.operationType = strdup(operationType->valuestring);
    }
    if (cJSON_IsString(action) && action->valuestring != NULL) {
        rule.action = strdup(action->valuestring);
    }

    if (cJSON_IsObject(conditions)) {
        cJSON *pathRegex = cJSON_GetObjectItemCaseSensitive(conditions, "pathRegex");
        cJSON *destinationType = cJSON_GetObjectItemCaseSensitive(conditions, "destinationType");
        cJSON *fileExtension = cJSON_GetObjectItemCaseSensitive(conditions, "fileExtension");
        cJSON *allowedApplications = cJSON_GetObjectItemCaseSensitive(conditions, "allowedApplications");
        cJSON *isSensitiveFile = cJSON_GetObjectItemCaseSensitive(conditions, "isSensitiveFile");
        cJSON *sensitiveDataType = cJSON_GetObjectItemCaseSensitive(conditions, "sensitiveDataType");

        if (cJSON_IsString(pathRegex) && pathRegex->valuestring != NULL) {
            rule.conditions.pathRegex = strdup(pathRegex->valuestring);
        }
        if (cJSON_IsString(destinationType) && destinationType->valuestring != NULL) {
            rule.conditions.destinationType = strdup(destinationType->valuestring);
        }
        if (cJSON_IsString(fileExtension) && fileExtension->valuestring != NULL) {
            rule.conditions.fileExtension = strdup(fileExtension->valuestring);
        }
        if (cJSON_IsArray(allowedApplications)) {
            rule.conditions.allowedApplicationsCount = cJSON_GetArraySize(allowedApplications);
            rule.conditions.allowedApplications = malloc(sizeof(char*) * rule.conditions.allowedApplicationsCount);
            for (int i = 0; i < rule.conditions.allowedApplicationsCount; i++) {
                cJSON *app = cJSON_GetArrayItem(allowedApplications, i);
                if (cJSON_IsString(app) && app->valuestring != NULL) {
                    rule.conditions.allowedApplications[i] = strdup(app->valuestring);
                }
            }
        }
        if (cJSON_IsBool(isSensitiveFile)) {
            rule.conditions.isSensitiveFile = cJSON_IsTrue(isSensitiveFile);
        }
        if (cJSON_IsString(sensitiveDataType) && sensitiveDataType->valuestring != NULL) {
            rule.conditions.sensitiveDataType = strdup(sensitiveDataType->valuestring);
        }
    }

    return rule;
}

// Function to parse all rules remains the same
Rules parseRules(const char *json) {
    Rules rules = {0};
    cJSON *root = cJSON_Parse(json);

    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON parsing error: %s\n", error_ptr);
        }
        return rules;
    }

    cJSON *dlpRules = cJSON_GetObjectItemCaseSensitive(root, "DLPRules");
    cJSON *dcRules = cJSON_GetObjectItemCaseSensitive(root, "DCRules");

    if (cJSON_IsArray(dlpRules)) {
        rules.dlpRulesCount = cJSON_GetArraySize(dlpRules);
        rules.dlpRules = malloc(sizeof(Rule) * rules.dlpRulesCount);
        if (rules.dlpRules == NULL) {
            fprintf(stderr, "Memory allocation failed for DLP rules\n");
            cJSON_Delete(root);
            return rules;
        }
        for (int i = 0; i < rules.dlpRulesCount; i++) {
            cJSON *rule = cJSON_GetArrayItem(dlpRules, i);
            rules.dlpRules[i] = parseRule(rule);
        }
    }

    if (cJSON_IsArray(dcRules)) {
        rules.dcRulesCount = cJSON_GetArraySize(dcRules);
        rules.dcRules = malloc(sizeof(Rule) * rules.dcRulesCount);
        if (rules.dcRules == NULL) {
            fprintf(stderr, "Memory allocation failed for DC rules\n");
            cJSON_Delete(root);
            return rules;
        }
        for (int i = 0; i < rules.dcRulesCount; i++) {
            cJSON *rule = cJSON_GetArrayItem(dcRules, i);
            rules.dcRules[i] = parseRule(rule);
        }
    }

    cJSON_Delete(root);
    return rules;
}

// Updated function to free allocated memory
void freeRules(Rules *rules) {
    for (int i = 0; i < rules->dlpRulesCount; i++) {
        free(rules->dlpRules[i].name);
        free(rules->dlpRules[i].operationType);
        free(rules->dlpRules[i].action);
        free(rules->dlpRules[i].conditions.pathRegex);
        free(rules->dlpRules[i].conditions.destinationType);
        free(rules->dlpRules[i].conditions.fileExtension);
        for (int j = 0; j < rules->dlpRules[i].conditions.allowedApplicationsCount; j++) {
            free(rules->dlpRules[i].conditions.allowedApplications[j]);
        }
        free(rules->dlpRules[i].conditions.allowedApplications);
        free(rules->dlpRules[i].conditions.sensitiveDataType);
    }
    free(rules->dlpRules);

    for (int i = 0; i < rules->dcRulesCount; i++) {
        free(rules->dcRules[i].name);
        free(rules->dcRules[i].operationType);
        free(rules->dcRules[i].action);
        free(rules->dcRules[i].conditions.pathRegex);
        free(rules->dcRules[i].conditions.destinationType);
        free(rules->dcRules[i].conditions.fileExtension);
        for (int j = 0; j < rules->dcRules[i].conditions.allowedApplicationsCount; j++) {
            free(rules->dcRules[i].conditions.allowedApplications[j]);
        }
        free(rules->dcRules[i].conditions.allowedApplications);
        free(rules->dcRules[i].conditions.sensitiveDataType);
    }
    free(rules->dcRules);
}

char *readFromFile(char *filename) {
    char *buffer = 0;
    long length;
    FILE* file = fopen(filename, "r");
    if (file) {
        fseek(file, 0, SEEK_END);
        length = ftell(file);
        fseek(file, 0, SEEK_SET);
        buffer = malloc(length);
        if (buffer) {
            fread(buffer, 1, length, file);
        }
        fclose(file);
    }

    return buffer;
}

Rules loadRulesFromFile(char *filename) {
    Rules rules = {0};
    char *json = readFromFile(filename); // Your JSON string here
    if (!json) {
        return rules;
    }

    rules = parseRules(json);
    free(json);
    return rules;
}

int isRulesNull(Rules rules) {
    return (!rules.dlpRules && !rules.dlpRulesCount && !rules.dcRules && !rules.dcRulesCount);
}

void printRules(Rules rules) {
    printf("DLP Rules:\n");
    for (int i = 0; i < rules.dlpRulesCount; i++) {
        printf("Rule %d:\n", i + 1);
        printf("  Name: %s\n", rules.dlpRules[i].name);
        printf("  Priority: %d\n", rules.dlpRules[i].priority);
        printf("  Operation Type: %s\n", rules.dlpRules[i].operationType);
        printf("  Action: %s\n", rules.dlpRules[i].action);
        printf("  Conditions:\n");
        if (rules.dlpRules[i].conditions.pathRegex)
            printf("    Path Regex: %s\n", rules.dlpRules[i].conditions.pathRegex);
        if (rules.dlpRules[i].conditions.destinationType)
            printf("    Destination Type: %s\n", rules.dlpRules[i].conditions.destinationType);
        if (rules.dlpRules[i].conditions.fileExtension)
            printf("    File Extension: %s\n", rules.dlpRules[i].conditions.fileExtension);
        if (rules.dlpRules[i].conditions.allowedApplicationsCount > 0) {
            printf("    Allowed Applications:\n");
            for (int j = 0; j < rules.dlpRules[i].conditions.allowedApplicationsCount; j++) {
                printf("      %s\n", rules.dlpRules[i].conditions.allowedApplications[j]);
            }
        }
        printf("    Is Sensitive File: %s\n", rules.dlpRules[i].conditions.isSensitiveFile ? "true" : "false");
        if (rules.dlpRules[i].conditions.sensitiveDataType)
            printf("    Sensitive Data Type: %s\n", rules.dlpRules[i].conditions.sensitiveDataType);
        printf("\n");
    }
}

int checkRuleConditions(Rule* rule, const char* filePath, const char* executablePath) {
    // Check pathRegex
    if (rule->conditions.pathRegex) {
        regex_t regex;
        int reti = regcomp(&regex, rule->conditions.pathRegex, REG_EXTENDED);
        if (reti) {
            fprintf(stderr, "Could not compile regex\n");
            return 0;
        }
        reti = regexec(&regex, filePath, 0, NULL, 0);
        regfree(&regex);
        if (reti) {
            return 0; // No match
        }
    }

    // Check allowedApplications
    if (rule->conditions.allowedApplications && rule->conditions.allowedApplicationsCount > 0) {
        int isAllowed = 0;
        for (int i = 0; i < rule->conditions.allowedApplicationsCount; i++) {
            if (strcmp(executablePath, rule->conditions.allowedApplications[i]) == 0) {
                isAllowed = 1;
                break;
            }
        }
        if (isAllowed) {
            return 0; // Executable in allowed list
        }
    }

    // Check isSensitiveFile
    if (rule->conditions.isSensitiveFile) {
        if (!is_file_sensitive(filePath)) {
            return 0;
        }
    }

    // Check sensitiveDataType
    if (rule->conditions.sensitiveDataType) {
        if (!contains_sensitive_data_type(filePath, rule->conditions.sensitiveDataType)) {
            return 0;
        }
    }

    // Check fileExtension
    if (rule->conditions.fileExtension) {
        char* extension = strrchr(filePath, '.');
        if (!extension || strcmp(extension, rule->conditions.fileExtension) != 0) {
            return 0;
        }
    }

    // All conditions met
    return 1;
}

//int main() {
//    // TODO: Read JSON from file and test
//    const char *json = readFromFile("example_rule.json"); // Your JSON string here
//    if (!json) {
//        //printf("%s\n", json);
//        perror("json read");
//        exit(EXIT_FAILURE);
//    }
//
//    Rules rules = parseRules(json);
//
//    // Print parsed rules
//    printf("DLP Rules:\n");
//    for (int i = 0; i < rules.dlpRulesCount; i++) {
//        printf("Rule %d:\n", i + 1);
//        printf("  Name: %s\n", rules.dlpRules[i].name);
//        printf("  Priority: %d\n", rules.dlpRules[i].priority);
//        printf("  Operation Type: %s\n", rules.dlpRules[i].operationType);
//        printf("  Action: %s\n", rules.dlpRules[i].action);
//        printf("  Conditions:\n");
//        if (rules.dlpRules[i].conditions.pathRegex)
//            printf("    Path Regex: %s\n", rules.dlpRules[i].conditions.pathRegex);
//        if (rules.dlpRules[i].conditions.destinationType)
//            printf("    Destination Type: %s\n", rules.dlpRules[i].conditions.destinationType);
//        if (rules.dlpRules[i].conditions.fileExtension)
//            printf("    File Extension: %s\n", rules.dlpRules[i].conditions.fileExtension);
//        if (rules.dlpRules[i].conditions.allowedApplicationsCount > 0) {
//            printf("    Allowed Applications:\n");
//            for (int j = 0; j < rules.dlpRules[i].conditions.allowedApplicationsCount; j++) {
//                printf("      %s\n", rules.dlpRules[i].conditions.allowedApplications[j]);
//            }
//        }
//        printf("    Is Sensitive File: %s\n", rules.dlpRules[i].conditions.isSensitiveFile ? "true" : "false");
//        if (rules.dlpRules[i].conditions.sensitiveDataType)
//            printf("    Sensitive Data Type: %s\n", rules.dlpRules[i].conditions.sensitiveDataType);
//        printf("\n");
//    }
//
//    // Free allocated memory
//    freeRules(&rules);
//
//    return 0;
//}
