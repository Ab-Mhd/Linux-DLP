#include "audit.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

char *audit_path;
AuditQueue audit_queue;
pthread_t audit_thread;
int audit_thread_running = 1;


void init_audit_queue(char *_audit_path) {
    audit_path = _audit_path;
    audit_queue.front = 0;
    audit_queue.rear = -1;
    audit_queue.count = 0;
    pthread_mutex_init(&audit_queue.mutex, NULL);
    pthread_cond_init(&audit_queue.cond, NULL);
}

void enqueue_audit_message(AuditMessage *msg) {
    pthread_mutex_lock(&audit_queue.mutex);
    if (audit_queue.count < MAX_QUEUE_SIZE) {
        audit_queue.rear = (audit_queue.rear + 1) % MAX_QUEUE_SIZE;
        audit_queue.messages[audit_queue.rear] = msg;
        audit_queue.count++;
        pthread_cond_signal(&audit_queue.cond);
    } else {
        fprintf(stderr, "Audit queue is full. Message dropped.\n");
        free(msg);
    }
    pthread_mutex_unlock(&audit_queue.mutex);
}

AuditMessage* dequeue_audit_message() {
    AuditMessage *msg = NULL;
    pthread_mutex_lock(&audit_queue.mutex);
    while (audit_queue.count == 0 && audit_thread_running) {
        pthread_cond_wait(&audit_queue.cond, &audit_queue.mutex);
    }
    if (audit_queue.count > 0) {
        msg = audit_queue.messages[audit_queue.front];
        audit_queue.front = (audit_queue.front + 1) % MAX_QUEUE_SIZE;
        audit_queue.count--;
    }
    pthread_mutex_unlock(&audit_queue.mutex);
    return msg;
}

void* audit_thread_function(void *arg) {
    // FILE *audit_file = fopen(AUDIT_PATH, "a");
    FILE *audit_file = fopen(audit_path, "a");
    if (audit_file == NULL) {
        fprintf(stderr, "Error opening audit file: %s\n", strerror(errno));
        return NULL;
    }

    while (audit_thread_running || audit_queue.count > 0) {
        AuditMessage *msg = dequeue_audit_message();
        if (msg != NULL) {
            fprintf(audit_file, "[%lu] - Rule: %s, Action: %s, File: %s, Application: %s\n",
                    msg->timestamp, msg->rule_name, msg->rule_action, msg->file_name, msg->application_name);
            fflush(audit_file);
            
            free(msg->rule_name);
            free(msg->rule_action);
            free(msg->file_name);
            free(msg->application_name);
            free(msg);
        }
    }

    fclose(audit_file);
    return NULL;
}