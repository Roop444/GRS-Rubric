#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <limits.h>

static void usage(const char *p) {
    fprintf(stderr, "Usage: %s <user> <read|write|exec> <path>\n", p);
    exit(1);
}

/*
 * Check basic UNIX permission bits
 * (Used only if ACLs do not grant access)
 */
static int check_mode_bits(uid_t uid, gid_t gid, struct stat *st, char op) {
    if (uid == st->st_uid) {
        if (op == 'r' && (st->st_mode & S_IRUSR)) return 1;
        if (op == 'w' && (st->st_mode & S_IWUSR)) return 1;
        if (op == 'x' && (st->st_mode & S_IXUSR)) return 1;
    }

    if (gid == st->st_gid) {
        if (op == 'r' && (st->st_mode & S_IRGRP)) return 1;
        if (op == 'w' && (st->st_mode & S_IWGRP)) return 1;
        if (op == 'x' && (st->st_mode & S_IXGRP)) return 1;
    }

    if (op == 'r' && (st->st_mode & S_IROTH)) return 1;
    if (op == 'w' && (st->st_mode & S_IWOTH)) return 1;
    if (op == 'x' && (st->st_mode & S_IXOTH)) return 1;

    return 0;
}

/*
 * Very conservative NFSv4 ACL reasoning:
 * - If any DENY exists for the user → deny
 * - If an explicit ALLOW exists → allow
 */
static int check_nfs4_acl(const char *user, const char *path, char op) {
    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "getfacl %s 2>/dev/null", path);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;  // unknown

    char line[512];
    int allow = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "user:") && strstr(line, user)) {
            if (strstr(line, ":deny")) {
                if ((op == 'r' && strchr(line, 'r')) ||
                    (op == 'w' && strchr(line, 'w')) ||
                    (op == 'x' && strchr(line, 'x'))) {
                    pclose(fp);
                    return 0;  // explicit deny
                }
            }

            if (strstr(line, ":allow")) {
                if ((op == 'r' && strchr(line, 'r')) ||
                    (op == 'w' && strchr(line, 'w')) ||
                    (op == 'x' && strchr(line, 'x'))) {
                    allow = 1;
                }
            }
        }
    }

    pclose(fp);
    return allow;
}

int main(int argc, char *argv[]) {
    if (argc != 4)
        usage(argv[0]);

    const char *user = argv[1];
    const char *opstr = argv[2];
    const char *path = argv[3];

    char op;
    if (!strcmp(opstr, "read")) op = 'r';
    else if (!strcmp(opstr, "write")) op = 'w';
    else if (!strcmp(opstr, "exec")) op = 'x';
    else usage(argv[0]);

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "Unknown user\n");
        return 1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat");
        return 1;
    }

    int acl = check_nfs4_acl(user, path, op);
    if (acl == 0) {
        printf("Prediction: DENY (ACL deny)\n");
        return 0;
    }
    if (acl == 1) {
        printf("Prediction: ALLOW (ACL allow)\n");
        return 0;
    }

    if (check_mode_bits(pw->pw_uid, pw->pw_gid, &st, op)) {
        printf("Prediction: ALLOW (mode bits)\n");
    } else {
        printf("Prediction: DENY\n");
    }

    return 0;
}
