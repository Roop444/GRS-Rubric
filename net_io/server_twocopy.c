#include "common.h"

void *client_handler(void *arg) {
    int fd = *(int *)arg;
    free(arg);

    message_t *msg = create_message(1024);
    char buffer[8192];

    while (1) {
        int offset = 0;
        for (int i = 0; i < FIELDS; i++) {
            memcpy(buffer + offset, msg->field[i], msg->len[i]);
            offset += msg->len[i];
        }
        send(fd, buffer, offset, 0);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = atoi(argv[1]);
    int sfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sfd, BACKLOG);

    while (1) {
        int *cfd = malloc(sizeof(int));
        *cfd = accept(sfd, NULL, NULL);
        pthread_t t;
        pthread_create(&t, NULL, client_handler, cfd);
    }
}

