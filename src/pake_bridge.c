#include "pake_bridge.h"
#include <openssl/curve25519.h>
#include <string.h>
void *pake_start(int server, const char *code, unsigned char message[32]) {
    const char *client = "DPDP-PAIR-2 client", *host = "DPDP-PAIR-2 server";
    const char *mine = server ? host : client, *theirs = server ? client : host;
    SPAKE2_CTX *ctx =
        SPAKE2_CTX_new(server ? spake2_role_bob : spake2_role_alice, (const unsigned char *)mine,
                       strlen(mine), (const unsigned char *)theirs, strlen(theirs));
    size_t n = 0;
    if (!ctx ||
        !SPAKE2_generate_msg(ctx, message, &n, 32, (const unsigned char *)code, strlen(code)) ||
        n != 32) {
        SPAKE2_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}
int pake_finish(void *ctx, const unsigned char message[32], unsigned char key[64]) {
    size_t n = 0;
    return SPAKE2_process_msg(ctx, key, &n, 64, message, 32) && n == 64 ? 0 : -1;
}
void pake_free(void *ctx) { SPAKE2_CTX_free(ctx); }
