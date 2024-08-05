#include "sensitive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define BUFFER_SIZE 1024

char* get_sensitive_tag(const char *filename) {
    ssize_t ret;
    char buffer[BUFFER_SIZE];
    char *ret_buf;

    // Get size of attribute and check if it exists
    ret = getxattr(filename, "user.sensitive", NULL, 0);
    if (ret == -1) {
//        perror("getxattr");
        return NULL;
    }

    if (ret > BUFFER_SIZE) {
//        fprintf(stderr, "buffer is too small\n");
        return NULL;
    }

    ret = getxattr(filename, "user.sensitive", buffer, BUFFER_SIZE);
    if (ret == -1) {
//        perror("getxattr");
        return NULL;
    }

    buffer[ret] = '\0';

    ret_buf = malloc(ret);
    memcpy(ret_buf, buffer, ret+1);
    return ret_buf;
}

char** split_string(const char *input, int *count) {
    char *str_copy = strdup(input); // Make a copy of the input string
    char *token;
    int tokens_count = 0;
    char **result = NULL;
    const char delim[2] = ",";

    if (str_copy == NULL) {
        perror("strdup");
        return NULL;
    }

    // Count the number of tokens
    token = strtok(str_copy, delim);
    while (token != NULL) {
        tokens_count++;
        token = strtok(NULL, delim);
    }

    // Allocate memory for the output array
    result = (char **)malloc(tokens_count * sizeof(char *));
    if (result == NULL) {
        perror("malloc");
        free(str_copy);
        return NULL;
    }

    // Tokenize the string again and store the tokens
    strcpy(str_copy, input); // Restore the original string
    token = strtok(str_copy, delim);
    int index = 0;
    while (token != NULL) {
        result[index] = strdup(token);
        if (result[index] == NULL) {
            perror("strdup");
            for (int i = 0; i < index; i++) {
                free(result[i]);
            }
            free(result);
            free(str_copy);
            return NULL;
        }
        index++;
        token = strtok(NULL, delim);
    }

    // Assign the output count
    *count = tokens_count;

    free(str_copy); // Free the duplicated string

    return result;
}

int is_file_sensitive(const char* filePath) {
    char *sensitive_tag = get_sensitive_tag(filePath);
    if (sensitive_tag == NULL) {
        return 0;
    }

    char **tags;
    int num_tags;
    tags = split_string(sensitive_tag, &num_tags);

    // Free everything
    free(sensitive_tag);
    for (int i = 0; i < num_tags; i++) {
        free(tags[i]);
    }
    free(tags);

    return num_tags > 0;
}

int contains_sensitive_data_type(const char* filePath, const char* dataType) {
    char *sensitive_tag = get_sensitive_tag(filePath);
    if (sensitive_tag == NULL) {
        return 0;
    }

    char **tags;
    int num_tags;
    tags = split_string(sensitive_tag, &num_tags);

    for (int i = 0; i < num_tags; i++) {
        if (strcmp(tags[i], dataType) == 0) {
            return 1;
        }
    }

    // Free everything
    free(sensitive_tag);
    for (int i = 0; i < num_tags; i++) {
        free(tags[i]);
    }
    free(tags);

    return 0;
}

//int main(int argc, char *argv[]) {
//    if (argc < 2) {
//        printf("Usage: %s <filename> [tag]\n", argv[0]);
//        exit(EXIT_FAILURE);
//    }
//
//    int is_sensitive = is_file_sensitive(argv[1]);
//    printf("File %s %s\n", argv[1], is_sensitive ? "is sensitive" : "is not sensitive");
//
//    // Test tagging
//    if (argc > 2) {
//        int has_tag = contains_sensitive_data_type(argv[1], argv[2]);
//        printf("File %s %s sensitive tag %s\n", argv[1], has_tag ? "has" : "does not have", argv[2]);
//    }
//}
