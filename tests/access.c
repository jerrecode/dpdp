#include "../src/security.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static void invoke(sec_ctx *s, const char *id) {
    pid_t p = fork();
    assert(p >= 0);
    if (!p) {
        int rc = access_command(s, "master", id, 0, NULL);
        _exit(rc ? 1 : 0);
    }
    int st;
    assert(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}
int main(void) {
    char dir[] = "/tmp/dpdp-access-XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("HOME", dir, 1) == 0);
    sec_ctx a, b;
    char path[640];
    snprintf(path, sizeof path, "%s/a", dir);
    assert(sec_init(&a, path, "00000000000000000000000000000001", "pc") == 0);
    snprintf(path, sizeof path, "%s/b", dir);
    assert(sec_init(&b, path, "00000000000000000000000000000002", "phone") == 0);
    struct json_object *identity = sec_identity(&b);
    assert(access_identity(&b, identity) == 0);
    const char *client = sec_str(identity, "ssh_client");
    assert(strlen(client) == 80);
    json_object_object_add(identity, "ssh_host", json_object_new_string(client));
    json_object_object_add(identity, "ssh_user", json_object_new_string("tester"));
    json_object_object_add(identity, "ssh_port", json_object_new_string("8022"));
    assert(access_validate(identity) == 0);
    struct json_object *bad = json_object_new_object();
    json_object_object_add(bad, "ssh_client",
                           json_object_new_string("command=evil ssh-ed25519 AAAA\n"));
    assert(access_validate(bad) < 0);
    json_object_put(bad);
    /* Simulate explicit local access setup, keeping tests independent of account name. */
    snprintf(path, sizeof path, "%s.access.json", a.config);
    const char *text = json_object_to_json_string(identity);
    assert(sec_atomic(path, text, strlen(text)) == 0);
    assert(sec_pin(&a, identity) == 0);
    assert(access_grant(&a, identity) == 0);
    assert(access_grant(&a, identity) == 0);
    snprintf(path, sizeof path, "%s/.ssh/authorized_keys", dir);
    char *keys = sec_read(path);
    assert(keys && strstr(keys, "dpdp-00000000000000000000000000000002"));
    char *line = strchr(keys, '\n');
    assert(line && line[1] == 0);
    free(keys);
    snprintf(path, sizeof path, "%s/bin", dir);
    assert(mkdir(path, 0700) == 0);
    snprintf(path, sizeof path, "%s/bin/ssh", dir);
    const char *script = "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$SSH_TEST_LOG\"\n";
    assert(sec_atomic(path, script, strlen(script)) == 0);
    assert(chmod(path, 0700) == 0);
    char envpath[1024];
    snprintf(envpath, sizeof envpath, "%s/bin:%s", dir, getenv("PATH"));
    assert(setenv("PATH", envpath, 1) == 0);
    snprintf(path, sizeof path, "%s/args", dir);
    assert(setenv("SSH_TEST_LOG", path, 1) == 0);
    sec_frame f = {.id = "00000000000000000000000000000002", .name = "phone", .ip = "192.0.2.2"};
    assert(sec_record_endpoint(&a, &f) == 0);
    invoke(&a, b.id);
    char *first = sec_read(path);
    assert(first && strstr(first, "StrictHostKeyChecking=yes") &&
           strstr(first, "IdentitiesOnly=yes") && strstr(first, "HostKeyAlias=dpdp-"));
    char *control = strstr(first, "ControlPath=");
    assert(control);
    char *end = strchr(control, '\n');
    assert(end);
    *end = 0;
    char oldcontrol[640];
    snprintf(oldcontrol, sizeof oldcontrol, "%s", control);
    free(first);
    snprintf(f.ip, sizeof f.ip, "192.0.2.3");
    assert(sec_record_endpoint(&a, &f) == 0);
    assert(sec_atomic(path, "", 0) == 0);
    invoke(&a, b.id);
    char *second = sec_read(path);
    assert(second && !strstr(second, oldcontrol));
    free(second);
    /* A helper with no control socket is still stopped by pairing supervision. */
    snprintf(path, sizeof path, "%s/bin/ssh", dir);
    const char *hold = "#!/bin/sh\nprintf '%s\\n' started >> \"$SSH_TEST_LOG\"\nexec sleep 30\n";
    assert(sec_atomic(path, hold, strlen(hold)) == 0);
    assert(chmod(path, 0700) == 0);
    snprintf(path, sizeof path, "%s/args", dir);
    assert(sec_atomic(path, "", 0) == 0);
    pid_t running = fork();
    assert(running >= 0);
    if (running == 0) {
        int rc = access_command(&a, "master", b.id, 0, NULL);
        _exit(rc ? 1 : 0);
    }
    for (unsigned i = 0; i < 100; i++) {
        char *log = sec_read(path);
        int started = log && strstr(log, "started");
        free(log);
        if (started)
            break;
        usleep(20000);
    }
    assert(sec_unpair(&a, b.id) == 0);
    int result = 0;
    uint64_t until = sec_now() + 5000;
    pid_t reaped;
    do {
        reaped = waitpid(running, &result, WNOHANG);
        if (!reaped)
            usleep(20000);
    } while (!reaped && sec_now() < until);
    if (!reaped) {
        kill(running, SIGKILL);
        waitpid(running, &result, 0);
    }
    assert(reaped == running && WIFEXITED(result) && WEXITSTATUS(result) == 1);

    snprintf(path, sizeof path, "%s/.ssh/authorized_keys", dir);
    keys = sec_read(path);
    assert(keys && !*keys);
    free(keys);
    assert(access_command(&a, "master", b.id, 0, NULL) < 0);
    json_object_put(identity);
    sec_free(&a);
    sec_free(&b);
    puts("OK: SSH key validation, authorization dedup/revoke, strict pins and endpoint-specific "
         "masters");
    return 0;
}
