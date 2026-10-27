#ifndef DPDP_PAKE_BRIDGE_H
#define DPDP_PAKE_BRIDGE_H
/* BoringSSL is isolated in this translation unit; no crypto primitives live here. */
void *pake_start(int server, const char *code, unsigned char message[32]);
int pake_finish(void *ctx, const unsigned char message[32], unsigned char key[64]);
void pake_free(void *ctx);
#endif
