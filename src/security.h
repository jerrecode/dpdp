#ifndef DPDP_SECURITY_H
#define DPDP_SECURITY_H
#include <gnutls/abstract.h>
#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>
#define SEC_PACKET 512
#define SEC_LIMIT 128
/* Context is process-local; keys are never sent. Public keys use DER SPKI hex. */
typedef struct {
    char config[512], id[33], name[49], public_hex[89], bind_ip[16];
    char nonce[33];
    uint64_t nonce_until;
    char confirmed[SEC_LIMIT][33];
    unsigned confirmed_count;
    gnutls_privkey_t key;
} sec_ctx;
typedef struct {
    char id[33], name[49], ip[16], nonce[33], echo[33];
    char kind;
} sec_frame;
int sec_init(sec_ctx *s, const char *config, const char *id, const char *name);
void sec_free(sec_ctx *s);
int sec_random_hex(char *out, size_t bytes);
uint64_t sec_now(void);
int sec_atomic(const char *path, const char *data, size_t len);
char *sec_read(const char *path);
struct json_object *sec_json(const char *text, size_t len);
const char *sec_str(struct json_object *o, const char *key);
struct json_object *sec_pairs(sec_ctx *s);
struct json_object *sec_find(sec_ctx *s, const char *selector);
int sec_pin(sec_ctx *s, struct json_object *identity);
int sec_epoch(sec_ctx *s, char out[33]);
int sec_pair_commit(sec_ctx *s, const char *id, const char *token);
int sec_unpair(sec_ctx *s, const char *selector);
int sec_sign(sec_ctx *s, const void *data, size_t len, char sig[129]);
int sec_verify(const char *pub, const void *data, size_t len, const char *sig);
int sec_challenge(sec_ctx *s);
int sec_packet(sec_ctx *s, char kind, const char *ip, const char *echo, char *out, size_t cap);
int sec_parse(sec_ctx *s, const char *wire, size_t n, const char *source, sec_frame *out);
int sec_record_endpoint(sec_ctx *s, const sec_frame *f);
int sec_confirm(sec_ctx *s, const sec_frame *f);
struct json_object *sec_identity(sec_ctx *s);
/* PAKE operates on an already connected stream; pairing CLI supplies TCP/time limits. */
int sec_pair_fd(sec_ctx *s, int fd, int server, const char *code, const char *expected_id);
int sec_pair_cli(sec_ctx *s, int server, const char *bind_ip, const char *peer_ip, unsigned port,
                 const char *expected_id);
int access_validate(struct json_object *identity);
int access_identity(sec_ctx *s, struct json_object *identity);
int access_grant(sec_ctx *s, struct json_object *identity);
int access_revoke(sec_ctx *s, const char *id);
int access_setup(sec_ctx *s, const char *host_key, unsigned port);
int access_command(sec_ctx *s, const char *action, const char *selector, int argc, char **argv);
#endif
