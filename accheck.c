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
 * NFSv4 ACL reasoning (correct parsing + logic)
 * Returns:
 *   1  → ALLOW
 *   0  → DENY
 *  -1  → NO MATCH (fallback to mode bits)
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

        // Skip comments
        if (line[0] == '#')
            continue;

        char name[64], perms[64], flags[64], type[64];

        // user:bob:rwx------:-------:allow
        if (sscanf(line, "user:%63[^:]:%63[^:]:%63[^:]:%63s",
                   name, perms, flags, type) == 4) {

            if (strncmp(name, user, strlen(user)) != 0)
                continue;
        }
        // everyone@:rwx------:-------:allow
        else if (sscanf(line, "everyone@:%63[^:]:%63[^:]:%63s",
                        perms, flags, type) == 3) {
            // matches everyone@
        }
        else {
            continue;
        }

        // Check permission ONLY in perms field
        int has_perm = 0;
        if (op == 'r' && strchr(perms, 'r')) has_perm = 1;
        if (op == 'w' && strchr(perms, 'w')) has_perm = 1;
        if (op == 'x' && strchr(perms, 'x')) has_perm = 1;

        if (!has_perm)
            continue;

        // DENY takes precedence
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

    if (allow)
        return 1;

    return -1;   // no ACL decision
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

    // 🔥 fallback to mode bits
    if (check_mode_bits(pw->pw_uid, pw->pw_gid, &st, op)) {
        printf("Prediction: ALLOW (mode bits)\n");
    } else {
        printf("Prediction: DENY\n");
    }

    return 0;
}
