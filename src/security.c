#define _POSIX_C_SOURCE 200809L
#include "security.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

uint64_t sec_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void hex(const unsigned char *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = h[in[i] >> 4];
        out[2 * i + 1] = h[in[i] & 15];
    }
    out[2 * n] = 0;
}
static int unhex(const char *in, unsigned char *out, size_t n) {
    if (strlen(in) != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (unsigned j = 0; j < 2; j++) {
            char c = in[2 * i + j];
            if (c >= '0' && c <= '9')
                v = v * 16 + c - '0';
            else if (c >= 'a' && c <= 'f')
                v = v * 16 + c - 'a' + 10;
            else
                return -1;
        }
        out[i] = (unsigned char)v;
    }
    return 0;
}
int sec_random_hex(char *out, size_t bytes) {
    unsigned char b[64];
    if (bytes > sizeof b || gnutls_rnd(GNUTLS_RND_RANDOM, b, bytes) < 0)
        return -1;
    hex(b, bytes, out);
    return 0;
}
const char *sec_str(struct json_object *o, const char *key) {
    struct json_object *v = NULL;
    if (!o || !json_object_is_type(o, json_type_object) || !json_object_object_get_ex(o, key, &v) ||
        !json_object_is_type(v, json_type_string))
        return "";
    const char *s = json_object_get_string(v);
    return strlen(s) == (size_t)json_object_get_string_len(v) ? s : "";
}
static int label(const char *s, size_t max) {
    size_t n = strlen(s);
    if (!n || n > max)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '_' && s[i] != '-')
            return 0;
    return 1;
}
char *sec_read(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > 1048576) {
        close(fd);
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    char *s = calloc(len + 1, 1);
    if (!s) {
        close(fd);
        return NULL;
    }
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = read(fd, s + pos, len - pos);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        pos += (size_t)n;
    }
    close(fd);
    if (pos != len || memchr(s, 0, len)) {
        free(s);
        return NULL;
    }
    return s;
}
int sec_atomic(const char *path, const char *data, size_t len) {
    char temp[640];
    if (snprintf(temp, sizeof temp, "%s.tmp.XXXXXX", path) >= (int)sizeof temp || len > 1048576)
        return -1;
    int fd = mkstemp(temp);
    if (fd < 0)
        return -1;
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = write(fd, data + pos, len - pos);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        pos += (size_t)n;
    }
    int ok = pos == len && fsync(fd) == 0;
    if (close(fd) < 0)
        ok = 0;
    if (ok && rename(temp, path) == 0) {
        char parent[640];
        snprintf(parent, sizeof parent, "%s", path);
        char *p = strrchr(parent, '/');
        if (p) {
            if (p == parent)
                p[1] = 0;
            else
                *p = 0;
        } else
            strcpy(parent, ".");
        int d = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (d < 0)
            return -1;
        int rc = fsync(d);
        close(d);
        return rc;
    }
    unlink(temp);
    return -1;
}
struct json_object *sec_json(const char *text, size_t len) {
    if (!text || !len || len > 1048576 || memchr(text, 0, len))
        return NULL;
    struct json_tokener *t = json_tokener_new();
    if (!t)
        return NULL;
    json_tokener_set_flags(t, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *o = json_tokener_parse_ex(t, text, (int)len);
    size_t end = json_tokener_get_parse_end(t);
    int ok = json_tokener_get_error(t) == json_tokener_success && o &&
             json_object_is_type(o, json_type_object);
    for (size_t i = end; ok && i < len; i++)
        if (!isspace((unsigned char)text[i]))
            ok = 0;
    json_tokener_free(t);
    if (!ok) {
        if (o)
            json_object_put(o);
        return NULL;
    }
    return o;
}
static int lock_file(const char *path) {
    int fd = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}
int sec_init(sec_ctx *s, const char *config, const char *id, const char *name) {
    memset(s, 0, sizeof *s);
    unsigned char check[16];
    if (strlen(config) > 500 || unhex(id, check, 16) || !label(name, 48) ||
        gnutls_global_init() < 0)
        return -1;
    snprintf(s->config, sizeof s->config, "%s", config);
    snprintf(s->id, sizeof s->id, "%s", id);
    snprintf(s->name, sizeof s->name, "%s", name);
    char path[560], lp[580];
    snprintf(path, sizeof path, "%s.signing.pem", config);
    snprintf(lp, sizeof lp, "%s.lock", path);
    int lock = lock_file(lp);
    if (lock < 0)
        return -1;
    gnutls_x509_privkey_t x = NULL;
    int rc = -1;
    if (gnutls_x509_privkey_init(&x) < 0)
        goto done;
    char *raw = sec_read(path);
    if (raw) {
        struct stat permissions;
        if (lstat(path, &permissions) || permissions.st_uid != getuid() ||
            (permissions.st_mode & 077)) {
            free(raw);
            goto done;
        }
        gnutls_datum_t pem = {(unsigned char *)raw, (unsigned)strlen(raw)};
        int err = gnutls_x509_privkey_import(x, &pem, GNUTLS_X509_FMT_PEM);
        free(raw);
        if (err < 0)
            goto done;
    } else {
        struct stat st;
        if (lstat(path, &st) == 0 || errno != ENOENT)
            goto done;
        if (gnutls_x509_privkey_generate(x, GNUTLS_PK_EDDSA_ED25519, 256, 0) < 0)
            goto done;
        gnutls_datum_t pem = {0};
        if (gnutls_x509_privkey_export2(x, GNUTLS_X509_FMT_PEM, &pem) < 0)
            goto done;
        int err = sec_atomic(path, (char *)pem.data, pem.size);
        gnutls_free(pem.data);
        if (err)
            goto done;
    }
    if (gnutls_x509_privkey_get_pk_algorithm(x) != GNUTLS_PK_EDDSA_ED25519 ||
        gnutls_privkey_init(&s->key) < 0 ||
        gnutls_privkey_import_x509(s->key, x, GNUTLS_PRIVKEY_IMPORT_COPY) < 0)
        goto done;
    gnutls_pubkey_t p = NULL;
    gnutls_datum_t der = {0};
    if (gnutls_pubkey_init(&p) < 0)
        goto done;
    int err = gnutls_pubkey_import_privkey(p, s->key, 0, 0);
    if (err >= 0)
        err = gnutls_pubkey_export2(p, GNUTLS_X509_FMT_DER, &der);
    gnutls_pubkey_deinit(p);
    if (err < 0)
        goto done;
    if (der.size == 44) {
        hex(der.data, der.size, s->public_hex);
        rc = 0;
    }
    gnutls_free(der.data);
done:
    if (x)
        gnutls_x509_privkey_deinit(x);
    flock(lock, LOCK_UN);
    close(lock);
    if (rc)
        sec_free(s);
    return rc;
}
void sec_free(sec_ctx *s) {
    if (s->key)
        gnutls_privkey_deinit(s->key);
    s->key = NULL;
}
int sec_sign(sec_ctx *s, const void *data, size_t len, char sig[129]) {
    gnutls_datum_t d = {(unsigned char *)data, (unsigned)len}, v = {0};
    if (!s->key || len > 16384 ||
        gnutls_privkey_sign_data2(s->key, GNUTLS_SIGN_EDDSA_ED25519, 0, &d, &v) < 0)
        return -1;
    int rc = v.size == 64 ? 0 : -1;
    if (!rc)
        hex(v.data, v.size, sig);
    gnutls_free(v.data);
    return rc;
}
int sec_verify(const char *pub, const void *data, size_t len, const char *sig) {
    unsigned char key[44], signature[64];
    if (unhex(pub, key, sizeof key) || unhex(sig, signature, sizeof signature) || len > 16384)
        return -1;
    gnutls_pubkey_t p = NULL;
    if (gnutls_pubkey_init(&p) < 0)
        return -1;
    gnutls_datum_t k = {key, sizeof key}, d = {(unsigned char *)data, (unsigned)len},
                   v = {signature, sizeof signature};
    int rc = gnutls_pubkey_import(p, &k, GNUTLS_X509_FMT_DER);
    if (rc >= 0 && gnutls_pubkey_get_pk_algorithm(p, NULL) != GNUTLS_PK_EDDSA_ED25519)
        rc = -1;
    if (rc >= 0)
        rc = gnutls_pubkey_verify_data2(p, GNUTLS_SIGN_EDDSA_ED25519, 0, &d, &v);
    gnutls_pubkey_deinit(p);
    return rc < 0 ? -1 : 0;
}
struct json_object *sec_pairs(sec_ctx *s) {
    char path[560];
    snprintf(path, sizeof path, "%s.paired.json", s->config);
    char *raw = sec_read(path);
    if (!raw) {
        struct stat st;
        if (lstat(path, &st) == 0 || errno != ENOENT)
            return NULL;
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "schema_version", json_object_new_int(1));
        json_object_object_add(o, "peers", json_object_new_object());
        return o;
    }
    struct json_object *o = sec_json(raw, strlen(raw));
    free(raw);
    struct json_object *p = NULL;
    if (o &&
        (!json_object_object_get_ex(o, "peers", &p) || !json_object_is_type(p, json_type_object))) {
        json_object_put(o);
        o = NULL;
    }
    return o;
}
static struct json_object *find_in(struct json_object *root, const char *selector,
                                   int include_revoked) {
    struct json_object *all = NULL, *found = NULL;
    if (!root || !json_object_object_get_ex(root, "peers", &all))
        return NULL;
    json_object_object_foreach(all, k, v) {
        struct json_object *rev = NULL, *pending = NULL;
        json_object_object_get_ex(v, "revoked", &rev);
        json_object_object_get_ex(v, "pending", &pending);
        if (!include_revoked && (json_object_get_boolean(rev) || json_object_get_boolean(pending)))
            continue;
        if (!strcmp(k, selector)) {
            return v;
        }
    }
    json_object_object_foreach(all, key, value) {
        (void)key;
        struct json_object *rev = NULL, *pending = NULL;
        json_object_object_get_ex(value, "revoked", &rev);
        json_object_object_get_ex(value, "pending", &pending);
        if (!include_revoked && (json_object_get_boolean(rev) || json_object_get_boolean(pending)))
            continue;
        if (!strcmp(sec_str(value, "name"), selector)) {
            if (found)
                return NULL;
            found = value;
        }
    }
    return found;
}
struct json_object *sec_find(sec_ctx *s, const char *selector) {
    struct json_object *o = sec_pairs(s);
    if (!o)
        return NULL;
    struct json_object *p = find_in(o, selector, 0);
    if (p)
        json_object_get(p);
    json_object_put(o);
    return p;
}
int sec_pin(sec_ctx *s, struct json_object *identity) {
    const char *id = sec_str(identity, "id"), *pub = sec_str(identity, "public_key"),
               *name = sec_str(identity, "name");
    unsigned char raw[16];
    char proof[129];
    if (unhex(id, raw, 16) || !strcmp(id, s->id) || !label(name, 48) || strlen(pub) != 88 ||
        sec_sign(s, "check", 5, proof) < 0)
        return -1; /* validate the public-key encoding independently of any signature */
    gnutls_pubkey_t key;
    unsigned char der[44];
    if (unhex(pub, der, 44) || gnutls_pubkey_init(&key) < 0)
        return -1;
    gnutls_datum_t d = {der, 44};
    int valid = gnutls_pubkey_import(key, &d, GNUTLS_X509_FMT_DER) >= 0 &&
                gnutls_pubkey_get_pk_algorithm(key, NULL) == GNUTLS_PK_EDDSA_ED25519;
    gnutls_pubkey_deinit(key);
    if (!valid)
        return -1;
    char path[560], lp[580];
    snprintf(path, sizeof path, "%s.paired.json", s->config);
    snprintf(lp, sizeof lp, "%s.lock", path);
    int lock = lock_file(lp);
    if (lock < 0)
        return -1;
    struct json_object *o = sec_pairs(s), *all = NULL, *old = NULL;
    int rc = -1;
    if (!o)
        goto done;
    json_object_object_get_ex(o, "peers", &all);
    if (json_object_object_get_ex(all, id, &old)) {
        if (strcmp(sec_str(old, "public_key"), pub))
            goto done;
    } else if (json_object_object_length(all) >= SEC_LIMIT)
        goto done;
    struct json_object *entry = NULL;
    const char *encoded = json_object_to_json_string_ext(identity, JSON_C_TO_STRING_PLAIN);
    entry = sec_json(encoded, strlen(encoded));
    if (!entry)
        goto done;
    json_object_object_add(entry, "revoked", json_object_new_boolean(0));
    json_object_object_add(all, id, entry);
    encoded = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY);
    rc = sec_atomic(path, encoded, strlen(encoded));
done:
    if (o)
        json_object_put(o);
    flock(lock, LOCK_UN);
    close(lock);
    return rc;
}
int sec_unpair(sec_ctx *s, const char *selector) {
    char path[560], lp[580];
    snprintf(path, sizeof path, "%s.paired.json", s->config);
    snprintf(lp, sizeof lp, "%s.lock", path);
    int lock = lock_file(lp);
    if (lock < 0)
        return -1;
    struct json_object *o = sec_pairs(s), *p = find_in(o, selector, 1);
    int rc = -1;
    if (p) {
        json_object_object_add(p, "revoked", json_object_new_boolean(1));
        const char *encoded = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY);
        rc = sec_atomic(path, encoded, strlen(encoded));
        if (!rc)
            rc = access_revoke(s, sec_str(p, "id"));
    }
    if (o)
        json_object_put(o);
    flock(lock, LOCK_UN);
    close(lock);
    return rc;
}
struct json_object *sec_identity(sec_ctx *s) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "version", json_object_new_int(1));
    json_object_object_add(o, "id", json_object_new_string(s->id));
    json_object_object_add(o, "name", json_object_new_string(s->name));
    json_object_object_add(o, "public_key", json_object_new_string(s->public_hex));
    return o;
}
int sec_challenge(sec_ctx *s) {
    if (sec_random_hex(s->nonce, 16))
        return -1;
    s->nonce_until = sec_now() + 45000;
    s->confirmed_count = 0;
    return 0;
}
int sec_packet(sec_ctx *s, char kind, const char *ip, const char *echo, char *out, size_t cap) {
    struct in_addr addr;
    if (!strchr("QAU", kind) || inet_pton(AF_INET, ip, &addr) != 1 || strlen(echo) > 32)
        return -1;
    int n =
        snprintf(out, cap, "DPDP/2|%c|%s|%s|%s|%s|%s", kind, s->id, s->name, ip, s->nonce, echo);
    char sig[129];
    if (n < 0 || (size_t)n >= cap || sec_sign(s, out, (size_t)n, sig))
        return -1;
    int extra = snprintf(out + n, cap - (size_t)n, "|%s", sig);
    return extra == 129 && (size_t)n + 129 < cap ? n + 129 : -1;
}
int sec_parse(sec_ctx *s, const char *wire, size_t n, const char *source, sec_frame *out) {
    if (n < 180 || n >= SEC_PACKET || memchr(wire, 0, n))
        return -1;
    char b[SEC_PACKET];
    memcpy(b, wire, n);
    b[n] = 0;
    char *sig = strrchr(b, '|');
    if (!sig)
        return -1;
    *sig++ = 0;
    size_t signed_len = (size_t)(sig - b - 1);
    char *parts[7];
    parts[0] = b;
    for (unsigned i = 0; i < 6; i++) {
        char *p = strchr(parts[i], '|');
        if (!p)
            return -1;
        *p = 0;
        parts[i + 1] = p + 1;
    }
    unsigned char id[16], nonce[16];
    if (strcmp(parts[0], "DPDP/2") || strlen(parts[1]) != 1 || !strchr("QAU", parts[1][0]) ||
        unhex(parts[2], id, 16) || !label(parts[3], 48) || strcmp(parts[4], source) ||
        unhex(parts[5], nonce, 16) || strcmp(parts[2], s->id) == 0)
        return -1;
    if (strcmp(parts[6], "-") && unhex(parts[6], nonce, 16))
        return -1;
    struct json_object *p = sec_find(s, parts[2]);
    if (!p)
        return -1;
    int ok = sec_verify(sec_str(p, "public_key"), wire, signed_len, sig) == 0;
    json_object_put(p);
    if (!ok)
        return -1;
    memset(out, 0, sizeof *out);
    snprintf(out->id, sizeof out->id, "%s", parts[2]);
    snprintf(out->name, sizeof out->name, "%s", parts[3]);
    snprintf(out->ip, sizeof out->ip, "%s", source);
    snprintf(out->nonce, sizeof out->nonce, "%s", parts[5]);
    snprintf(out->echo, sizeof out->echo, "%s", parts[6]);
    out->kind = parts[1][0];
    return 0;
}
int sec_confirm(sec_ctx *s, const sec_frame *f) {
    if (f->kind != 'A' || sec_now() > s->nonce_until || strcmp(s->nonce, f->echo))
        return 0;
    for (unsigned i = 0; i < s->confirmed_count; i++)
        if (!strcmp(s->confirmed[i], f->id))
            return 0;
    if (s->confirmed_count >= SEC_LIMIT)
        return 0;
    snprintf(s->confirmed[s->confirmed_count++], 33, "%s", f->id);
    return 1;
}

int sec_record_endpoint(sec_ctx *s, const sec_frame *f) {
    char path[560], lp[580];
    snprintf(path, sizeof path, "%s.paired.json", s->config);
    snprintf(lp, sizeof lp, "%s.lock", path);
    int lock = lock_file(lp);
    if (lock < 0)
        return -1;
    struct json_object *o = sec_pairs(s), *p = find_in(o, f->id, 0);
    int rc = -1;
    if (p) {
        json_object_object_add(p, "name", json_object_new_string(f->name));
        json_object_object_add(p, "last_ip", json_object_new_string(f->ip));
        json_object_object_add(p, "last_verified_unix", json_object_new_int64(time(NULL)));
        const char *encoded = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY);
        rc = sec_atomic(path, encoded, strlen(encoded));
    }
    if (o)
        json_object_put(o);
    flock(lock, LOCK_UN);
    close(lock);
    return rc;
}
