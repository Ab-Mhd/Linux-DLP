//
// Created by user on 7/23/24.
//

#ifndef FANOTIFY_SENSITIVE_H
#define FANOTIFY_SENSITIVE_H

char* get_sensitive_tag(const char *filename);
char** split_string(const char *input, int *count);
extern int is_file_sensitive(const char* filePath);
extern int contains_sensitive_data_type(const char* filePath, const char* dataType);

#endif //FANOTIFY_SENSITIVE_H
