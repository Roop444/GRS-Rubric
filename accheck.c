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

        char *saveptr;
        char *tag = strtok_r(line, ":", &saveptr);
        char *name = strtok_r(NULL, ":", &saveptr);
        char *perms = strtok_r(NULL, ":", &saveptr);
        char *type = strtok_r(NULL, ":", &saveptr);

        if (!tag || !perms || !type)
            continue;

        int match = 0;

        // Match user:bob or user:bob@
        if (strcmp(tag, "user") == 0 && name) {
            if (strncmp(name, user, strlen(user)) == 0)
                match = 1;
        }

        // Match everyone@
        if (strcmp(tag, "everyone@") == 0)
            match = 1;

        if (!match)
            continue;

        // ✅ Check permission ONLY in perms field
        int has_perm = 0;
        if (op == 'r' && strchr(perms, 'r')) has_perm = 1;
        if (op == 'w' && strchr(perms, 'w')) has_perm = 1;
        if (op == 'x' && strchr(perms, 'x')) has_perm = 1;

        if (!has_perm)
            continue;

        // ✅ DENY only if permission matches
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
