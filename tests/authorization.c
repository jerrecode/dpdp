#define main dpdp_program_main
#include "../src/dpdp.c"
#undef main
#include <assert.h>
int main(void) {
    char dir[] = "/tmp/dpdp-auth-XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("HOME", dir, 1) == 0);
    snprintf(cfg.registry, sizeof cfg.registry, "%s/registry", dir);
    cfg.auto_ssh = 0;
    char c[512];
    snprintf(c, sizeof c, "%s/a", dir);
    assert(sec_init(&security, c, "00000000000000000000000000000001", "pc") == 0);
    security_ready = 1;
    sec_ctx remote;
    snprintf(c, sizeof c, "%s/b", dir);
    assert(sec_init(&remote, c, "00000000000000000000000000000002", "phone") == 0);
    struct json_object *identity = sec_identity(&remote);
    assert(sec_pin(&security, identity) == 0);
    json_object_put(identity);
    peer_t *p = upsert(remote.id, "phone", "192.0.2.2");
    assert(p && !p->authenticated);
    struct json_object *root = read_json(cfg.registry), *all = obj_field(root, "peers"),
                       *item = obj_field(all, "phone");
    set_bool(item, "trusted", 1);
    struct json_object *services = json_object_new_array(), *service = json_object_new_object();
    set_bool(service, "enabled", 1);
    set_string(service, "exec", "/bin/true");
    json_object_array_add(services, service);
    json_object_object_add(item, "services", services);
    const char *encoded = json_object_to_json_string(root);
    assert(write_atomic(cfg.registry, encoded, strlen(encoded)) == 0);
    json_object_put(root);
    assert(start_services(p) == 0); /* legacy trusted=true is insufficient */
    p = upsert_verified(remote.id, "phone", "192.0.2.2", 1);
    assert(p->authenticated && p->dispatched);
    p = upsert(remote.id, "spoofed-name", "192.0.2.99");
    assert(!strcmp(p->ip, "192.0.2.2") && !strcmp(p->name, "phone") && p->authenticated);
    /* An unverified-peer flood cannot reserve all slots against a paired node. */
    peer_count = MAX_PEERS;
    memset(peers, 0, sizeof peers);
    for (unsigned i = 0; i < MAX_PEERS; i++)
        snprintf(peers[i].id, sizeof peers[i].id, "ffffffffffffffffffffffff%08x", i);
    p = upsert_verified(remote.id, "phone", "192.0.2.2", 1);
    assert(p && p->authenticated);
    assert(sec_unpair(&security, remote.id) == 0);
    assert(start_services(p) == 0);
    while (waitpid(-1, NULL, 0) > 0) {
    }
    sec_free(&remote);
    sec_free(&security);
    puts("OK: legacy hooks denied, authenticated IP cannot be overwritten, revocation denied");
    return 0;
}
