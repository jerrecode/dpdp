#include "../src/security.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    char dir[] = "/tmp/dpdp-security-XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("HOME", dir, 1) == 0);
    char aconf[512], bconf[512];
    snprintf(aconf, sizeof aconf, "%s/a", dir);
    snprintf(bconf, sizeof bconf, "%s/b", dir);
    sec_ctx a, b;
    assert(sec_init(&a, aconf, "00000000000000000000000000000001", "same") == 0);
    assert(sec_init(&b, bconf, "00000000000000000000000000000002", "same") == 0);
    char saved_pub[89];
    snprintf(saved_pub, sizeof saved_pub, "%s", a.public_hex);
    sec_free(&a);
    assert(sec_init(&a, aconf, "00000000000000000000000000000001", "same") == 0);
    assert(!strcmp(saved_pub, a.public_hex));
    struct json_object *ai = sec_identity(&a), *bi = sec_identity(&b);
    assert(ai && bi);
    /* Enrollment data must never import remote assertions of endpoint verification. */
    json_object_object_add(bi, "last_ip", json_object_new_string("192.0.2.99"));
    json_object_object_add(bi, "last_verified_unix", json_object_new_int64(9999999999LL));
    json_object_object_add(bi, "trusted", json_object_new_boolean(1));
    assert(sec_pin(&a, bi) == 0 && sec_pin(&b, ai) == 0);
    struct json_object *pinned = sec_find(&a, b.id), *unexpected = NULL;
    assert(pinned);
    assert(!json_object_object_get_ex(pinned, "last_ip", &unexpected));
    assert(!json_object_object_get_ex(pinned, "last_verified_unix", &unexpected));
    assert(!json_object_object_get_ex(pinned, "trusted", &unexpected));
    json_object_put(pinned);
    /* Re-enrollment preserves local extensions but requires a fresh endpoint proof. */
    struct json_object *store = sec_pairs(&a), *peers = NULL, *entry = NULL;
    assert(json_object_object_get_ex(store, "peers", &peers));
    assert(json_object_object_get_ex(peers, b.id, &entry));
    json_object_object_add(entry, "local_note", json_object_new_string("keep"));
    json_object_object_add(entry, "last_ip", json_object_new_string("192.0.2.2"));
    json_object_object_add(entry, "last_verified_unix", json_object_new_int64(123));
    char pairs_path[560];
    snprintf(pairs_path, sizeof pairs_path, "%s.paired.json", aconf);
    const char *encoded = json_object_to_json_string_ext(store, JSON_C_TO_STRING_PLAIN);
    assert(sec_atomic(pairs_path, encoded, strlen(encoded)) == 0);
    json_object_put(store);
    assert(sec_pin(&a, bi) == 0);
    pinned = sec_find(&a, b.id);
    assert(pinned && !strcmp(sec_str(pinned, "local_note"), "keep"));
    assert(!json_object_object_get_ex(pinned, "last_ip", &unexpected));
    assert(!json_object_object_get_ex(pinned, "last_verified_unix", &unexpected));
    json_object_put(pinned);
    char wire[SEC_PACKET];
    sec_frame f;
    assert(sec_challenge(&a) == 0 && sec_challenge(&b) == 0);
    assert(sec_packet(&b, 'A', "192.0.2.2", a.nonce, wire, sizeof wire) > 0);
    assert(sec_parse(&a, wire, strlen(wire), "192.0.2.2", &f) == 0 && sec_confirm(&a, &f) == 1);
    assert(sec_confirm(&a, &f) == 0); /* duplicate response */
    assert(sec_parse(&a, wire, strlen(wire), "192.0.2.3", &f) < 0);
    wire[20] ^= 1;
    assert(sec_parse(&a, wire, strlen(wire), "192.0.2.2", &f) < 0);
    wire[20] ^= 1;
    assert(sec_challenge(&a) == 0);
    assert(sec_parse(&a, wire, strlen(wire), "192.0.2.2", &f) == 0 && sec_confirm(&a, &f) == 0);
    a.nonce_until = 0;
    assert(sec_confirm(&a, &f) == 0);
    /* A conflicting key cannot take over the same legacy ID, even with matching name. */
    json_object_object_add(bi, "public_key", json_object_new_string(a.public_hex));
    assert(sec_pin(&a, bi) < 0);
    assert(sec_unpair(&a, b.id) == 0);
    assert(sec_parse(&a, wire, strlen(wire), "192.0.2.2", &f) < 0);
    /* Revocation wins both before staging and after a pending enrollment. */
    json_object_object_add(bi, "public_key", json_object_new_string(b.public_hex));
    char epoch[33];
    assert(sec_epoch(&a, epoch) == 0);
    json_object_object_add(bi, "pending", json_object_new_boolean(1));
    json_object_object_add(bi, "enrollment_epoch", json_object_new_string(epoch));
    json_object_object_add(bi, "pairing_token",
                           json_object_new_string("00000000000000000000000000000001"));
    assert(sec_pin(&a, bi) == 0);
    assert(sec_unpair(&a, b.id) == 0);
    assert(sec_pair_commit(&a, b.id, "00000000000000000000000000000001") < 0);
    assert(sec_pin(&a, bi) < 0); /* handshake started in an older revocation epoch */
    assert(sec_find(&a, b.id) == NULL);
    assert(sec_json("{}junk", 6) == NULL);
    json_object_put(ai);
    json_object_put(bi);
    sec_free(&a);
    sec_free(&b);
    puts("OK: signed endpoint proofs, replay/forgery rejection and key pinning/revocation");
    return 0;
}
