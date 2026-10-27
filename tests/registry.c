/* Exercise real persistence without requiring a multicast-capable interface. */
#define main dpdp_program_main
#include "../src/dpdp.c"
#undef main
#include <assert.h>

static void save_root(struct json_object *root) {
    const char *s=json_object_to_json_string(root);
    assert(write_atomic(cfg.registry,s,strlen(s))==0);
}
static void check_peer(const char *id,const char *custom,int trusted) {
    struct json_object *root=read_json(cfg.registry),*all=obj_field(root,"peers"),*found=NULL;
    unsigned count=0;
    json_object_object_foreach(all,k,v) {
        (void)k;
        if(!strcmp(str_field(v,"id"),id)){found=v;count++;}
    }
    assert(count==1);
    assert(!strcmp(str_field(found,"custom"),custom));
    assert(json_object_get_boolean(obj_field(found,"trusted"))==trusted);
    json_object_put(root);
}
int main(void) {
    char dir[]="/tmp/dpdp-registry-XXXXXX";assert(mkdtemp(dir));
    snprintf(cfg.registry,sizeof cfg.registry,"%s/peers.json",dir);
    peer_t a={.id="12345678000000000000000000000001",.name="same",.ip="192.0.2.1",.online=1};
    peer_t b={.id="12345678000000000000000000000002",.name="same",.ip="192.0.2.2",.online=1};
    peer_t c={.id="12345678000000000000000000000003",.name="same",.ip="192.0.2.3",.online=1};
    assert(sync_registry(&a)==0);assert(sync_registry(&b)==0);
    struct json_object *root=read_json(cfg.registry),*all=obj_field(root,"peers");
    { json_object_object_foreach(all,k,v) {
        (void)k;set_string(v,"custom",str_field(v,"id"));set_bool(v,"trusted",1);
        json_object_array_add(obj_field(v,"services"),json_object_new_string("preserve-service"));
    } }
    save_root(root);json_object_put(root);
    assert(sync_registry(&c)==0);
    check_peer(a.id,a.id,1);check_peer(b.id,b.id,1);check_peer(c.id,"",0);
    /* Rename into keys deliberately occupied by unrelated metadata, including null. */
    root=read_json(cfg.registry);all=obj_field(root,"peers");
    json_object_object_add(all,"renamed",json_object_new_string("operator value"));
    char full[96];snprintf(full,sizeof full,"renamed-%s",a.id);
    json_object_object_add(all,full,NULL);
    save_root(root);json_object_put(root);
    copy(a.name,sizeof a.name,"renamed");assert(sync_registry(&a)==0);
    check_peer(a.id,a.id,1);check_peer(b.id,b.id,1);
    root=read_json(cfg.registry);all=obj_field(root,"peers");
    assert(!strcmp(json_object_get_string(obj_field(all,"renamed")),"operator value"));
    struct json_object *v=NULL;assert(json_object_object_get_ex(all,full,&v) && v==NULL);
    { json_object_object_foreach(all,k,entry_item) {
        (void)k;
        if(!strcmp(str_field(entry_item,"id"),a.id))assert(json_object_array_length(obj_field(entry_item,"services"))==1);
    } }
    /* Existing identity under a long operator key must be found without truncation. */
    struct json_object *item=NULL;char oldkey[128]={0};
    { json_object_object_foreach(all,k,entry) {
        if(!strcmp(str_field(entry,"id"),b.id)){item=json_object_get(entry);copy(oldkey,sizeof oldkey,k);break;}
    } }
    assert(item);json_object_object_del(all,oldkey);
    char longkey[300];memset(longkey,'x',sizeof longkey-1);longkey[sizeof longkey-1]=0;
    json_object_object_add(all,longkey,item);save_root(root);json_object_put(root);
    assert(sync_registry(&b)==0);check_peer(b.id,b.id,1);
    unlink(cfg.registry);char lock[550];snprintf(lock,sizeof lock,"%s.lock",cfg.registry);unlink(lock);rmdir(dir);
    puts("OK: colliding names and renamed peers preserve identity-owned metadata");
    return 0;
}
