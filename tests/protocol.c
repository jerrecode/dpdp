#define main dpdp_program_main
#include "../src/dpdp.c"
#undef main
#include <assert.h>

static int parse(const char *wire,size_t n) {
    char buf[MAX_PACKET+1],kind,id[33],name[49];
    assert(n<=MAX_PACKET);memcpy(buf,wire,n);
    return parse_packet(buf,n,&kind,id,name);
}
int main(void) {
    const char *prefix="DPDP/1|A|00112233445566778899aabbccddeeff|node|";
    char wire[MAX_PACKET+1];
    snprintf(wire,sizeof wire,"%s1",prefix);assert(parse(wire,strlen(wire))==0);
    snprintf(wire,sizeof wire,"%s18446744073709551615",prefix);assert(parse(wire,strlen(wire))==0);
    /* The old tokenizer collapses empty fields and ignores final separators. */
    const char *bad[]={
        "DPDP/1||A|00112233445566778899aabbccddeeff|node|1",
        "DPDP/1|A|00112233445566778899aabbccddeeff|node|1|",
        "DPDP/1|A|00112233445566778899aabbccddeeff|node|1||",
        "DPDP/1|A|00112233445566778899aabbccddeeff||1",
        "DPDP/1|A|00112233445566778899aabbccddeeff|node|18446744073709551616"
    };
    for(size_t i=0;i<sizeof bad/sizeof bad[0];i++)assert(parse(bad[i],strlen(bad[i]))<0);
    snprintf(wire,sizeof wire,"%s1",prefix);size_t n=strlen(wire);
    memcpy(wire+n,"\0hidden",7);assert(parse(wire,n+7)<0);
    for(size_t i=0;i<45;i++)assert(parse(wire,i)<0);
    memset(wire,'x',MAX_PACKET);assert(parse(wire,MAX_PACKET)<0);
    puts("OK: exact protocol fields, sequence bounds and embedded-NUL rejection");
    return 0;
}
