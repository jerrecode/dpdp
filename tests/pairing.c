#include "../src/security.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
static void exchange(sec_ctx *a, sec_ctx *b, int correct) {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        int rc = sec_pair_fd(a, fds[1], 1, "012345", NULL);
        close(fds[1]);
        _exit((rc == 0) == correct ? 0 : 1);
    }
    close(fds[1]);
    int rc = sec_pair_fd(b, fds[0], 0, correct ? "012345" : "012346", a->id);
    close(fds[0]);
    assert((rc == 0) == correct);
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(void) {
    char dir[] = "/tmp/dpdp-pair-XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("HOME", dir, 1) == 0);
    char p[512];
    sec_ctx a, b;
    snprintf(p, sizeof p, "%s/a", dir);
    assert(sec_init(&a, p, "00000000000000000000000000000001", "debian") == 0);
    snprintf(p, sizeof p, "%s/b", dir);
    assert(sec_init(&b, p, "00000000000000000000000000000002", "phone") == 0);
    exchange(&a, &b, 0);
    assert(sec_find(&a, b.id) == NULL && sec_find(&b, a.id) == NULL);
    exchange(&a, &b, 1);
    struct json_object *v = sec_find(&a, b.id);
    assert(v);
    json_object_put(v);
    v = sec_find(&b, a.id);
    assert(v);
    json_object_put(v);
    exchange(&a, &b, 1);
    sec_free(&a);
    sec_free(&b);
    puts("OK: real SPAKE2/TLS1.3 wrong-code rejection, mutual pinning and idempotent retry");
    return 0;
}
