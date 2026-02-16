#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define FIELDS 8
#define BACKLOG 10

typedef struct {
    char *field[FIELDS];
    size_t len[FIELDS];
} message_t;

static inline message_t *create_message(size_t size) {
    message_t *m = malloc(sizeof(message_t));
    for (int i = 0; i < FIELDS; i++) {
        m->field[i] = malloc(size);
        memset(m->field[i], 'A' + i, size);
        m->len[i] = size;
    }
    return m;
}

#endif

