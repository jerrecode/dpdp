#define _POSIX_C_SOURCE 200809L
#include "security.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/crypto.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static int run(char **argv) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (!pid) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}
static int key_valid(const char *key) {
    if (strlen(key) != 80 || strncmp(key, "ssh-ed25519 ", 12))
        return 0;
    gnutls_datum_t b64 = {(unsigned char *)key + 12, 68}, raw = {0};
    if (gnutls_base64_decode2(&b64, &raw) < 0)
        return 0;
    static const unsigned char header[] = {0,   0,   0,   11,  's', 's', 'h', '-', 'e', 'd',
                                           '2', '5', '5', '1', '9', 0,   0,   0,   32};
    int valid = raw.size == 51 && !memcmp(raw.data, header, sizeof header);
    gnutls_free(raw.data);
    return valid;
}
static char *load_key(const char *path) {
    char *raw = sec_read(path);
    if (!raw)
        return NULL;
    char *space = strchr(raw, ' ');
    if (space) {
        char *end = space + 1;
        end += strcspn(end, " \t\r\n");
        *end = 0;
    }
    if (!key_valid(raw)) {
        free(raw);
        return NULL;
    }
    return raw;
}
static int user_valid(const char *s) {
    size_t n = strlen(s);
    if (!n || n > 64 || s[0] == '-')
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
              (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-' || s[i] == '.'))
            return 0;
    return strcmp(s, "root") != 0;
}
static unsigned port_value(const char *s) {
    if (!*s)
        return 0;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return 0;
    char *end;
    unsigned long n = strtoul(s, &end, 10);
    return !*end && n > 0 && n <= 65535 ? (unsigned)n : 0;
}
int access_validate(struct json_object *identity) {
    if (!key_valid(sec_str(identity, "ssh_client")))
        return -1;
    const char *host = sec_str(identity, "ssh_host");
    if (*host && (!key_valid(host) || !user_valid(sec_str(identity, "ssh_user")) ||
                  !port_value(sec_str(identity, "ssh_port"))))
        return -1;
    return 0;
}
static struct json_object *local_access(sec_ctx *s) {
    char path[560];
    snprintf(path, sizeof path, "%s.access.json", s->config);
    char *raw = sec_read(path);
    if (!raw)
        return NULL;
    struct json_object *o = sec_json(raw, strlen(raw));
    free(raw);
    return o;
}
int access_identity(sec_ctx *s, struct json_object *identity) {
    char key[560], pub[580], lp[580];
    snprintf(key, sizeof key, "%s.ssh", s->config);
    snprintf(pub, sizeof pub, "%s.pub", key);
    snprintf(lp, sizeof lp, "%s.lock", key);
    int lock = open(lp, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0)
        return -1;
    if (flock(lock, LOCK_EX) < 0) {
        close(lock);
        return -1;
    }
    struct stat st;
    int rc = -1;
    if (lstat(key, &st) < 0) {
        if (errno != ENOENT)
            goto done;
        char *argv[] = {"ssh-keygen", "-q",   "-t", "ed25519", "-N", "",
                        "-C",         "dpdp", "-f", key,       NULL};
        if (run(argv))
            goto done;
    } else if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 077))
        goto done;
    char *client = load_key(pub);
    if (!client)
        goto done;
    json_object_object_add(identity, "ssh_client", json_object_new_string(client));
    free(client);
    struct json_object *o = local_access(s);
    if (o) {
        if (!key_valid(sec_str(o, "ssh_host")) || !user_valid(sec_str(o, "ssh_user")) ||
            !port_value(sec_str(o, "ssh_port"))) {
            json_object_put(o);
            goto done;
        }
        const char *names[] = {"ssh_host", "ssh_user", "ssh_port"};
        for (unsigned i = 0; i < 3; i++)
            json_object_object_add(identity, names[i],
                                   json_object_new_string(sec_str(o, names[i])));
        json_object_put(o);
    }
    rc = 0;
done:
    flock(lock, LOCK_UN);
    close(lock);
    return rc;
}
int access_setup(sec_ctx *s, const char *host_key, unsigned port) {
    if (!port || port > 65535)
        return -1;
    struct passwd *pw = getpwuid(getuid());
    if (!pw || !user_valid(pw->pw_name))
        return -1;
    char *key = load_key(host_key);
    if (!key)
        return -1;
    struct json_object *o = json_object_new_object();
    char number[12];
    snprintf(number, sizeof number, "%u", port);
    json_object_object_add(o, "ssh_host", json_object_new_string(key));
    json_object_object_add(o, "ssh_user", json_object_new_string(pw->pw_name));
    json_object_object_add(o, "ssh_port", json_object_new_string(number));
    free(key);
    char path[560];
    snprintf(path, sizeof path, "%s.access.json", s->config);
    const char *encoded = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY);
    int rc = sec_atomic(path, encoded, strlen(encoded));
    json_object_put(o);
    return rc;
}
static int edit_authorized(const char *id, const char *key) {
    const char *home = getenv("HOME");
    if (!home || strlen(home) > 450 || strlen(id) != 32)
        return -1;
    char dir[512], path[560], lockpath[580];
    snprintf(dir, sizeof dir, "%s/.ssh", home);
    struct stat st;
    if (lstat(dir, &st) < 0) {
        if (errno != ENOENT || mkdir(dir, 0700))
            return -1;
    } else if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 022))
        return -1;
    snprintf(path, sizeof path, "%s/authorized_keys", dir);
    snprintf(lockpath, sizeof lockpath, "%s.dpdp.lock", path);
    int lock = open(lockpath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0)
        return -1;
    if (flock(lock, LOCK_EX)) {
        close(lock);
        return -1;
    }
    int rc = -1;
    char *old = sec_read(path);
    if (!old) {
        if (lstat(path, &st) == 0 || errno != ENOENT)
            goto done;
        old = strdup("");
        if (!old)
            goto done;
    }
    char *next = calloc(1048577, 1);
    if (!next)
        goto done;
    char marker[48];
    snprintf(marker, sizeof marker, " dpdp-%s", id);
    size_t used = 0, marklen = strlen(marker);
    for (char *line = old; *line;) {
        char *end = strchr(line, '\n');
        size_t n = end ? (size_t)(end - line) : strlen(line);
        int managed = n >= marklen && !memcmp(line + n - marklen, marker, marklen);
        if (!managed) {
            if (used + n + 1 > 1048576) {
                free(next);
                goto done;
            }
            memcpy(next + used, line, n);
            used += n;
            next[used++] = '\n';
        }
        if (!end)
            break;
        line = end + 1;
    }
    if (key) {
        int n = snprintf(next + used, 1048577 - used, "%s%s\n", key, marker);
        if (n < 0 || (size_t)n > 1048576 - used) {
            free(next);
            goto done;
        }
        used += (size_t)n;
    }
    rc = sec_atomic(path, next, used);
    free(next);
done:
    free(old);
    flock(lock, LOCK_UN);
    close(lock);
    return rc;
}
int access_grant(sec_ctx *s, struct json_object *identity) {
    if (access_validate(identity))
        return -1;
    struct json_object *local = local_access(s);
    if (!local)
        return 0;
    json_object_put(local);
    return edit_authorized(sec_str(identity, "id"), sec_str(identity, "ssh_client"));
}
static int config_directory(sec_ctx *s, char out[512]) {
    snprintf(out, 512, "%s", s->config);
    char *p = strrchr(out, '/');
    if (!p) {
        strcpy(out, ".");
        return 0;
    }
    if (p == out)
        p[1] = 0;
    else
        *p = 0;
    return 0;
}
int access_revoke(sec_ctx *s, const char *id) {
    int rc = edit_authorized(id, NULL);
    char dir[512], prefix[48];
    config_directory(s, dir);
    snprintf(prefix, sizeof prefix, "cm-%s-", id);
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, prefix, strlen(prefix)))
            continue;
        char path[800];
        if (snprintf(path, sizeof path, "%s/%s", dir, e->d_name) >= (int)sizeof path) {
            rc = -1;
            continue;
        }
        struct stat st;
        if (lstat(path, &st) || !S_ISSOCK(st.st_mode) || st.st_uid != getuid())
            continue;
        char *argv[] = {"ssh", "-F", "/dev/null", "-S", path, "-O", "exit", "127.0.0.1", NULL};
        if (run(argv))
            rc = -1;
    }
    closedir(d);
    return rc;
}
int access_command(sec_ctx *s, const char *action, const char *selector, int argc, char **args) {
    struct json_object *p = sec_find(s, selector);
    if (!p)
        return -1;
    int rc = -1;
    const char *id = sec_str(p, "id"), *ip = sec_str(p, "last_ip"), *user = sec_str(p, "ssh_user"),
               *hostkey = sec_str(p, "ssh_host");
    struct in_addr addr;
    unsigned port = port_value(sec_str(p, "ssh_port"));
    if (!key_valid(hostkey) || !user_valid(user) || !port || inet_pton(AF_INET, ip, &addr) != 1)
        goto done;
    struct json_object *seen = NULL;
    json_object_object_get_ex(p, "last_verified_unix", &seen);
    int64_t age = (int64_t)time(NULL) - json_object_get_int64(seen);
    if (age < 0 || age > 90)
        goto done;
    char known[560], clientkey[560], alias[64], knownopt[600], hostopt[96], controlopt[680],
        directory[512], control[640], endpoint[256], digest[25], target[96];
    snprintf(known, sizeof known, "%s.known-%s", s->config, id);
    snprintf(clientkey, sizeof clientkey, "%s.ssh", s->config);
    snprintf(alias, sizeof alias, "dpdp-%s", id);
    char line[256];
    int len = snprintf(line, sizeof line, "%s %s\n", alias, hostkey);
    if (len < 0 || sec_atomic(known, line, (size_t)len))
        goto done;
    snprintf(knownopt, sizeof knownopt, "UserKnownHostsFile=%s", known);
    snprintf(hostopt, sizeof hostopt, "HostKeyAlias=%s", alias);
    snprintf(endpoint, sizeof endpoint, "%s|%s|%u|%s", sec_str(p, "public_key"), ip, port, user);
    unsigned char hash[32];
    if (gnutls_hash_fast(GNUTLS_DIG_SHA256, endpoint, strlen(endpoint), hash) < 0)
        goto done;
    for (unsigned i = 0; i < 12; i++)
        snprintf(digest + 2 * i, 3, "%02x", hash[i]);
    config_directory(s, directory);
    snprintf(control, sizeof control, "%s/cm-%s-%s", directory, id, digest);
    if (strlen(control) > 100)
        goto done;
    snprintf(controlopt, sizeof controlopt, "ControlPath=%s", control);
    snprintf(target, sizeof target, "%s@%s", user, ip);
    char number[12];
    snprintf(number, sizeof number, "%u", port);
    char *argv[96];
    unsigned n = 0;
    int scp = !strcmp(action, "send") || !strcmp(action, "receive");
    argv[n++] = scp ? "scp" : !strcmp(action, "sftp") ? "sftp" : "ssh";
#define ARG(x)                                                                                     \
    do {                                                                                           \
        if (n >= 94)                                                                               \
            goto done;                                                                             \
        argv[n++] = (char *)(x);                                                                   \
    } while (0)
    ARG("-F");
    ARG("/dev/null");
    ARG("-o");
    ARG("StrictHostKeyChecking=yes");
    ARG("-o");
    ARG("GlobalKnownHostsFile=/dev/null");
    ARG("-o");
    ARG(knownopt);
    ARG("-o");
    ARG(hostopt);
    ARG("-o");
    ARG("IdentitiesOnly=yes");
    ARG("-o");
    ARG("BatchMode=yes");
    ARG("-o");
    ARG("ConnectTimeout=5");
    ARG("-o");
    ARG("ConnectionAttempts=1");
    ARG("-o");
    ARG("ServerAliveInterval=15");
    ARG("-o");
    ARG("ServerAliveCountMax=3");
    ARG("-o");
    ARG("HostKeyAlgorithms=ssh-ed25519");
    ARG("-o");
    ARG(controlopt);
    ARG("-o");
    ARG(!strcmp(action,"master")?"ControlMaster=yes":"ControlMaster=auto");
    ARG("-o");
    ARG(!strcmp(action,"master")?"ControlPersist=no":"ControlPersist=60");
    ARG("-i");
    ARG(clientkey);
    ARG(scp || !strcmp(action, "sftp") ? "-P" : "-p");
    ARG(number);
    char bindopt[48];
    if(s->bind_ip[0]){snprintf(bindopt,sizeof bindopt,"BindAddress=%s",s->bind_ip);ARG("-o");ARG(bindopt);}
    char remote[2048];
    if (scp) {
        if (argc != 2 || strlen(args[0]) > 1500 || strlen(args[1]) > 1500)
            goto done;
        const char *path = !strcmp(action, "send") ? args[1] : args[0];
        snprintf(remote, sizeof remote, "%s:%s", target, path);
        ARG("--");
        ARG(!strcmp(action, "send") ? args[0] : remote);
        ARG(!strcmp(action, "send") ? remote : args[1]);
    } else if (!strcmp(action, "master")) {
        if (argc)
            goto done;
        ARG("-N");
        ARG(target);
    } else if (!strcmp(action, "forward")) {
        if (argc != 1 || args[0][0] == '-')
            goto done;
        ARG("-N");
        ARG("-o");
        ARG("ExitOnForwardFailure=yes");
        ARG("-L");
        ARG(args[0]);
        ARG(target);
    } else if (!strcmp(action, "sftp")) {
        if (argc)
            goto done;
        ARG(target);
    } else {
        ARG(target);
        for (int i = 0; i < argc; i++)
            ARG(args[i]);
    }
    argv[n] = NULL;
    execvp(argv[0], argv);
    perror("OpenSSH");
#undef ARG
done:
    json_object_put(p);
    return rc;
}
