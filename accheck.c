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
 * Check directory traversal (execute permission on all parent dirs)
 */
static int check_traversal(const char *path) {
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';

    char *p = tmp;

    while ((p = strchr(p + 1, '/')) != NULL) {
        *p = '\0';

        struct stat st;
        if (stat(tmp, &st) == 0) {
            if (!(st.st_mode & S_IXOTH)) {
                return 0; // traversal denied
            }
        }

        *p = '/';
    }

    return 1;
}

/*
 * Check basic UNIX permission bits
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
 * NFSv4 ACL reasoning (improved)
 */
static int check_nfs4_acl(const char *user, const char *path, char op) {
    char cmd[PATH_MAX + 64];
    snprintf(cmd, sizeof(cmd), "getfacl %s 2>/dev/null", path);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    char line[512];
    int allow = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;

        char *tag = strtok(line, ":");
        char *name = strtok(NULL, ":");
        char *perms = strtok(NULL, ":");
        char *type = strtok(NULL, ":");

        if (!tag || !name || !perms || !type)
            continue;

        int match = 0;

        // Match user:bob or user:bob@
        if (strcmp(tag, "user") == 0) {
            if (strncmp(name, user, strlen(user)) == 0)
                match = 1;
        }

        // Match everyone@
        if (strcmp(tag, "everyone@") == 0)
            match = 1;

        if (!match)
            continue;

        // Check permission
        int has_perm = 0;
        if (op == 'r' && strchr(perms, 'r')) has_perm = 1;
        if (op == 'w' && strchr(perms, 'w')) has_perm = 1;
        if (op == 'x' && strchr(perms, 'x')) has_perm = 1;

        if (!has_perm)
            continue;

        // DENY first
        if (strcmp(type, "deny") == 0) {
            pclose(fp);
            return 0;
        }

        // ALLOW
        if (strcmp(type, "allow") == 0) {
            allow = 1;
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

    // ✅ NEW: traversal check
    if (!check_traversal(path)) {
        printf("Prediction: DENY (directory traversal)\n");
        return 0;
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
