#define _POSIX_C_SOURCE 200809L
#include "pake_bridge.h"
#include "security.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/crypto.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>
#define PAIR_BYTES 8192
#define PAIR_MS 10000
static int wait_io(int fd, int writing, uint64_t deadline) {
    for (;;) {
        uint64_t now = sec_now();
        if (now >= deadline)
            return -1;
        struct pollfd p = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int rc = poll(&p, 1, (int)(deadline - now));
        if (rc < 0 && errno == EINTR)
            continue;
        return rc > 0 && !(p.revents & (POLLERR | POLLNVAL)) ? 0 : -1;
    }
}
static int transfer(gnutls_session_t tls, int fd, void *buf, size_t n, int writing,
                    uint64_t until) {
    size_t used = 0;
    while (used < n) {
        if (sec_now() >= until)
            return -1;
        ssize_t rc = writing ? gnutls_record_send(tls, (char *)buf + used, n - used)
                             : gnutls_record_recv(tls, (char *)buf + used, n - used);
        if (rc == GNUTLS_E_INTERRUPTED)
            continue;
        if (rc == GNUTLS_E_AGAIN) {
            if (wait_io(fd, gnutls_record_get_direction(tls), until))
                return -1;
            continue;
        }
        if (rc <= 0)
            return -1;
        used += (size_t)rc;
    }
    return 0;
}
static int send_json(gnutls_session_t tls, int fd, struct json_object *o, uint64_t until) {
    const char *s = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    size_t n = strlen(s);
    if (!n || n > PAIR_BYTES)
        return -1;
    uint32_t len = htonl((uint32_t)n);
    return transfer(tls, fd, &len, 4, 1, until) || transfer(tls, fd, (void *)s, n, 1, until) ? -1
                                                                                             : 0;
}
static struct json_object *recv_json(gnutls_session_t tls, int fd, uint64_t until) {
    uint32_t len = 0;
    if (transfer(tls, fd, &len, 4, 0, until))
        return NULL;
    len = ntohl(len);
    if (!len || len > PAIR_BYTES)
        return NULL;
    char data[PAIR_BYTES];
    if (transfer(tls, fd, data, len, 0, until))
        return NULL;
    return sec_json(data, len);
}
static int raw_transfer(int fd, void *data, size_t n, int writing, uint64_t until) {
    size_t used = 0;
    while (used < n) {
        ssize_t rc = writing ? send(fd, (char *)data + used, n - used, MSG_NOSIGNAL)
                             : recv(fd, (char *)data + used, n - used, 0);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_io(fd, writing, until))
                return -1;
            continue;
        }
        if (rc <= 0 || sec_now() >= until)
            return -1;
        used += (size_t)rc;
    }
    return 0;
}
static int psk_credentials(gnutls_session_t tls, const char *username, gnutls_datum_t *key) {
    if (strcmp(username, "dpdp-pair-v2"))
        return -1;
    key->size = 64;
    key->data = gnutls_malloc(64);
    if (!key->data)
        return -1;
    memcpy(key->data, gnutls_session_get_ptr(tls), 64);
    return 0;
}
static int valid_code(const char *s) {
    if (strlen(s) != 6)
        return 0;
    for (unsigned i = 0; i < 6; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    return 1;
}
static int pair_until(sec_ctx *s, int fd, int server, const char *code, const char *expected_id,
                      uint64_t until) {
    if (!valid_code(code))
        return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    const char *stage = "TLS setup";
    int rc = -1;
    gnutls_session_t tls = NULL;
    gnutls_psk_server_credentials_t sc = NULL;
    gnutls_psk_client_credentials_t cc = NULL;
    void *pake = NULL;
    unsigned char shared[64] = {0};
    struct json_object *identity = NULL, *envelope = NULL, *incoming = NULL, *remote = NULL;

    unsigned char message[32], other_msg[32];
    stage = "SPAKE2 exchange";
    pake = pake_start(server, code, message);
    if (!pake || raw_transfer(fd, message, 32, 1, until) ||
        raw_transfer(fd, other_msg, 32, 0, until) || pake_finish(pake, other_msg, shared))
        goto done;
    if (gnutls_init(&tls, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) | GNUTLS_NONBLOCK |
                              GNUTLS_NO_TICKETS) < 0)
        goto done;
    if (gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:+DHE-PSK:+ECDHE-PSK",
                                   NULL) < 0)
        goto done;
    if (server) {
        if (gnutls_psk_allocate_server_credentials(&sc) < 0)
            goto done;
        gnutls_psk_set_server_credentials_function(sc, psk_credentials);
        gnutls_session_set_ptr(tls, shared);
        if (gnutls_credentials_set(tls, GNUTLS_CRD_PSK, sc) < 0)
            goto done;
    } else {
        gnutls_datum_t key = {shared, sizeof shared};
        if (gnutls_psk_allocate_client_credentials(&cc) < 0 ||
            gnutls_psk_set_client_credentials(cc, "dpdp-pair-v2", &key, GNUTLS_PSK_KEY_RAW) < 0 ||
            gnutls_credentials_set(tls, GNUTLS_CRD_PSK, cc) < 0)
            goto done;
    }
    stage = "TLS handshake";
    gnutls_transport_set_int(tls, fd);
    for (;;) {
        if (sec_now() >= until)
            goto done;
        int err = gnutls_handshake(tls);
        if (err == 0)
            break;
        if (err == GNUTLS_E_INTERRUPTED)
            continue;
        if (err != GNUTLS_E_AGAIN || wait_io(fd, gnutls_record_get_direction(tls), until)) {
            fprintf(stderr, "TLS pairing: %s\n", gnutls_strerror(err));
            goto done;
        }
    }
    if (gnutls_protocol_get_version(tls) != GNUTLS_TLS1_3)
        goto done;
    stage = "channel binding";
    unsigned char exporter[32];
    if (gnutls_prf_rfc5705(tls, 12, "dpdp-pair-v2", 0, NULL, sizeof exporter, (char *)exporter) < 0)
        goto done;
    char channel[65];
    for (unsigned i = 0; i < 32; i++)
        snprintf(channel + i * 2, 3, "%02x", exporter[i]);
    stage = "local SSH identity";
    identity = sec_identity(s);
    if (!identity || access_identity(s, identity))
        goto done;
    const char *payload = json_object_to_json_string_ext(identity, JSON_C_TO_STRING_PLAIN);
    char bound[PAIR_BYTES * 2], signature[129];
    int n =
        snprintf(bound, sizeof bound, "DPDP-PAIR-2|%c|%s|%s", server ? 'S' : 'C', channel, payload);
    if (n < 0 || (size_t)n >= sizeof bound || sec_sign(s, bound, (size_t)n, signature))
        goto done;
    stage = "identity exchange";
    envelope = json_object_new_object();
    json_object_object_add(envelope, "payload", json_object_new_string(payload));
    json_object_object_add(envelope, "signature", json_object_new_string(signature));
    if (send_json(tls, fd, envelope, until))
        goto done;
    incoming = recv_json(tls, fd, until);
    if (!incoming)
        goto done;
    const char *other = sec_str(incoming, "payload");
    remote = sec_json(other, strlen(other));
    if (!remote)
        goto done;
    n = snprintf(bound, sizeof bound, "DPDP-PAIR-2|%c|%s|%s", server ? 'C' : 'S', channel, other);
    if (n < 0 || (size_t)n >= sizeof bound ||
        sec_verify(sec_str(remote, "public_key"), bound, (size_t)n, sec_str(incoming, "signature")))
        goto done;
    if (expected_id && strcmp(expected_id, sec_str(remote, "id")))
        goto done;
    stage = "pin identity";
    json_object_object_add(remote, "pending", json_object_new_boolean(1));
    if (access_validate(remote) || sec_pin(s, remote))
        goto done;
    /* A partially committed exchange is recoverable by explicitly pairing again
       with the same keys. Different keys never replace existing pins. */
    stage = "commit/SSH authorization";
    char ack = 'K', peer_ack = 0;
    if (transfer(tls, fd, &ack, 1, 1, until) || transfer(tls, fd, &peer_ack, 1, 0, until) ||
        peer_ack != 'K' || access_grant(s, remote))
        goto done;
    json_object_object_add(remote, "pending", json_object_new_boolean(0));
    if (sec_pin(s, remote)) {
        access_revoke(s, sec_str(remote, "id"));
        goto done;
    }
    fprintf(stderr, "Paired %s (%s)\n", sec_str(remote, "name"), sec_str(remote, "id"));
    rc = 0;
done:
    if (rc)
        fprintf(stderr, "Pairing failed at %s\n", stage);
    if (remote)
        json_object_put(remote);
    if (incoming)
        json_object_put(incoming);
    if (envelope)
        json_object_put(envelope);
    if (identity)
        json_object_put(identity);
    if (tls)
        gnutls_deinit(tls);
    pake_free(pake);
    gnutls_memset(shared, 0, sizeof shared);
    if (sc)
        gnutls_psk_free_server_credentials(sc);
    if (cc)
        gnutls_psk_free_client_credentials(cc);
    return rc;
}
int sec_pair_fd(sec_ctx *s, int fd, int server, const char *code, const char *expected_id) {
    return pair_until(s, fd, server, code, expected_id, sec_now() + PAIR_MS);
}
int sec_pair_cli(sec_ctx *s, int server, const char *bind_ip, const char *peer_ip, unsigned port,
                 const char *expected_id) {
    if (port > 65535 || port < 1024)
        return -1;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, server ? bind_ip : peer_ip, &addr.sin_addr) != 1)
        return -1;
    char code[16] = {0};
    int listener = -1, lock = -1, rc = -1;
    if (server) {
        char lockpath[560];
        snprintf(lockpath, sizeof lockpath, "%s.pairing.lock", s->config);
        lock = open(lockpath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) < 0)
            goto done;
        uint32_t value;
        do {
            if (gnutls_rnd(GNUTLS_RND_RANDOM, &value, sizeof value) < 0)
                goto done;
        } while (value >= 4294000000U);
        snprintf(code, sizeof code, "%06u", value % 1000000);
        listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (listener < 0)
            goto done;
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(listener, (struct sockaddr *)&addr, sizeof addr) || listen(listener, 2))
            goto done;
        fprintf(stderr, "Pairing code: %s\nValid for 120 seconds / 3 attempts on %s:%u.\n", code,
                bind_ip, port);
        fflush(stderr);
        uint64_t until = sec_now() + 120000;
        for (unsigned tries = 0; tries < 3; tries++) {
            if (wait_io(listener, 0, until))
                break;
            int fd = accept(listener, NULL, NULL);
            if (fd < 0) {
                if (errno == EINTR) {
                    tries--;
                    continue;
                }
                break;
            }
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            uint64_t attempt_end = sec_now() + PAIR_MS;
            rc = pair_until(s, fd, 1, code, NULL, attempt_end < until ? attempt_end : until);
            close(fd);
            if (!rc)
                break;
            fprintf(stderr, "Pairing attempt failed (%u of 3).\n", tries + 1);
        }
    } else {
        fprintf(stderr, "Enter the six-digit code displayed on Debian: ");
        fflush(stderr);
        if (!fgets(code, sizeof code, stdin))
            goto done;
        code[strcspn(code, "\r\n")] = 0;
        if (!valid_code(code))
            goto done;
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
            goto done;
        struct sockaddr_in local = {.sin_family = AF_INET};
        if (inet_pton(AF_INET, bind_ip, &local.sin_addr) != 1 ||
            bind(fd, (struct sockaddr *)&local, sizeof local)) {
            close(fd);
            goto done;
        }
        int err = connect(fd, (struct sockaddr *)&addr, sizeof addr);
        if (err < 0 && errno != EINPROGRESS) {
            close(fd);
            goto done;
        }
        int status = 0;
        socklen_t size = sizeof status;
        if ((err < 0 && wait_io(fd, 1, sec_now() + 5000)) ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &size) || status) {
            close(fd);
            goto done;
        }
        rc = sec_pair_fd(s, fd, 0, code, expected_id);
        close(fd);
    }
done:
    memset(code, 0, sizeof code);
    if (listener >= 0)
        close(listener);
    if (lock >= 0)
        close(lock);
    return rc;
}
