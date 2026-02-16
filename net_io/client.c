#include "common.h"
#include <time.h>

int main(int argc, char *argv[]) {
    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    char buf[8192];
    time_t start = time(NULL);

    while (time(NULL) - start < duration) {
        recv(fd, buf, sizeof(buf), 0);
    }
}

