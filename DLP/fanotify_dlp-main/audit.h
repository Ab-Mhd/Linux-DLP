#ifndef FANOTIFY_AUDIT_H
#define FANOTIFY_AUDIT_H

#include <pthread.h>
#define MAX_QUEUE_SIZE 1000


typedef struct {
    char *rule_name;
    char *rule_action;
    char *file_name;
    char *application_name;
    time_t timestamp;
} AuditMessage;

typedef struct {
    AuditMessage *messages[MAX_QUEUE_SIZE];
    int front;
    int rear;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} AuditQueue;

extern char *audit_path;
extern AuditQueue audit_queue;
extern pthread_t audit_thread;
extern int audit_thread_running;

void init_audit_queue(char *_audit_path);
void enqueue_audit_message(AuditMessage *msg);
AuditMessage* dequeue_audit_message();
void* audit_thread_function(void *arg);

#endif /* FANOTIFY_AUDIT_H */