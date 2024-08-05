#include <fcntl.h>
#include <linux/fanotify.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <cjson/cJSON.h>
#include <linux/limits.h>
#include <pthread.h>
#include "rules.h"
#include "sensitive.h"
#include "audit.h"


#define AUDIT_PATH "./audit.log"
#define MAX_LOG_LENGTH 1024

char* get_executable_path(pid_t pid);
int check_file_and_app(const char *file_path, pid_t pid);
int rule_triggered(const char *file_path, char *application_path, Rule rule);
void audit_event(const char *rule_name, const char *rule_action, const char *file_name, const char *application_name);

Rules rules;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <rule file> <audit file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int fd, ret;
    char buf[4096];
    char path[PATH_MAX];
    struct fanotify_event_metadata *metadata;
    struct fanotify_response response;

    // Load DLP rules
    rules = loadRulesFromFile(argv[1]);
    if (isRulesNull(rules)) {
        perror("rule load");
        exit(EXIT_FAILURE);
    }
    printRules(rules);

    // Load audit thread
    init_audit_queue(argv[2]);
    pthread_create(&audit_thread, NULL, audit_thread_function, NULL);

    // Initialize fanotify
    fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
                       O_RDONLY | __O_LARGEFILE);
    if (fd == -1) {
        perror("fanotify_init");
        exit(EXIT_FAILURE);
    }

    // Mark the directory to monitor
    // "FAN_MARK_MOUNT" seems to mean that we mark all files on the mount, and so will have to handle all of those
    // events
    ret = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                        FAN_OPEN_PERM, AT_FDCWD, "/");
    if (ret == -1) {
        perror("fanotify_mark");
        exit(EXIT_FAILURE);
    }

    while (1) {
        ret = read(fd, buf, sizeof(buf));
        if (ret == -1 && errno != EAGAIN) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        metadata = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(metadata, ret)) {
            if (metadata->mask & FAN_OPEN_PERM) {
                // Get file path
                sprintf(path, "/proc/self/fd/%d", metadata->fd);
                ssize_t read_bytes = readlink(path, path, sizeof(path));
                // Set the null byte at the end of path
                if (read_bytes != -1 && read_bytes < PATH_MAX) {
                    path[read_bytes] = '\0';
                }

                // Implement your decision logic here
                int allow_access = check_file_and_app(path, metadata->pid);

                // Respond to the permission event
                response.fd = metadata->fd;
                response.response = allow_access ? FAN_ALLOW : FAN_DENY;
                write(fd, &response, sizeof(response));
            }
            close(metadata->fd);
            metadata = FAN_EVENT_NEXT(metadata, ret);
        }
    }

    freeRules(&rules);

    audit_thread_running = 0;
    pthread_cond_signal(&audit_queue.cond);  // Wake up the audit thread if it's waiting
    pthread_join(audit_thread, NULL);
    pthread_mutex_destroy(&audit_queue.mutex);
    pthread_cond_destroy(&audit_queue.cond);

    return 0;
}

char* get_executable_path(pid_t pid) {
    char* path = NULL;
    ssize_t len;
    char proc_path[256];

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    path = malloc(PATH_MAX);
    if (path == NULL) {
        perror("malloc");
        return NULL;
    }

    len = readlink(proc_path, path, PATH_MAX - 1);
    if (len == -1) {
        perror("readlink");
        free(path);
        return NULL;
    }

    path[len] = '\0';

    return path;
}

int check_file_and_app(const char *file_path, pid_t pid) {
    int shouldBlock = 0;
    char* path = get_executable_path(pid);

    // Loop over all rules - we'll only handle DLP rules for now and ignore DC rules
    for (int r = 0; r < rules.dlpRulesCount; r++) {
        // Check if rule was triggered, and if so perform its action
        int triggered = checkRuleConditions(&rules.dlpRules[r], file_path, path);
        if (triggered) {
            printf("Triggered rule '%s'.  Action %s\n", rules.dlpRules[r].name, rules.dlpRules[r].action);
			if (strcmp("block", rules.dlpRules[r].action) == 0) {
				shouldBlock = 1;
                audit_event(rules.dlpRules[r].name, rules.dlpRules[r].action, file_path, path);
			} else if (strcmp("log", rules.dlpRules[r].action) == 0) {
                audit_event(rules.dlpRules[r].name, rules.dlpRules[r].action, file_path, path);
			} else {
				// Handles ignore, etc.
				continue;
			}
        }
    }

    free(path);
    return !shouldBlock;
}

// void audit_event(const char *rule_name, const char *rule_action, const char *file_name, const char *application_name) {
//     printf("AUDIT\n");
//     FILE* audit_file;
//     time_t now;
//     struct tm *local_time;
//     char timestamp[32];
//     char log_entry[MAX_LOG_LENGTH];

//     time(&now);
//     snprintf(log_entry, MAX_LOG_LENGTH, "[%lu] - Rule: %s, Action: %s, File: %s, Application: %s\n",
//              now, rule_name, rule_action, file_name, application_name);
//     printf(log_entry);

// //    audit_file = fopen(AUDIT_PATH, "a");
// //    if (audit_file == NULL) {
// //        fprintf(stderr, "Error opening audit file: %s\n", strerror(errno));
// //        return;
// //    }

// //    if (fputs(log_entry, audit_file) == EOF) {
// //        fprintf(stderr, "Error writing to audit file: %s\n", strerror(errno));
// //    }

// //    fclose(audit_file);
// }


void audit_event(const char *rule_name, const char *rule_action, const char *file_name, const char *application_name) {
    AuditMessage *msg = malloc(sizeof(AuditMessage));
    if (msg == NULL) {
        fprintf(stderr, "Failed to allocate memory for audit message\n");
        return;
    }

    msg->rule_name = strdup(rule_name);
    msg->rule_action = strdup(rule_action);
    msg->file_name = strdup(file_name);
    msg->application_name = strdup(application_name);
    time(&msg->timestamp);

    enqueue_audit_message(msg);
}