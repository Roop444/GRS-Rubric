#include "common.h"
#include <sys/uio.h>

void *client_handler(void *arg) {
    int fd = *(int *)arg;
    free(arg);

    message_t *msg = create_message(1024);
    struct iovec iov[FIELDS];
    struct msghdr hdr = {0};

    for (int i = 0; i < FIELDS; i++) {
        iov[i].iov_base = msg->field[i];
        iov[i].iov_len = msg->len[i];
    }

    hdr.msg_iov = iov;
    hdr.msg_iovlen = FIELDS;

    while (1) {
        sendmsg(fd, &hdr, 0);
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

