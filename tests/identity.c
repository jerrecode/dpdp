#define main dpdp_program_main
#include "../src/dpdp.c"
#undef main
#include <assert.h>

int main(void) {
    char dir[]="/tmp/dpdp-identity-XXXXXX";assert(mkdtemp(dir));
    snprintf(cfg.config,sizeof cfg.config,"%s/config",dir);
    int gate[2],results[2];assert(pipe(gate)==0);assert(pipe(results)==0);
    enum { CHILDREN=24 };pid_t children[CHILDREN];
    for(unsigned i=0;i<CHILDREN;i++) {
        children[i]=fork();assert(children[i]>=0);
        if(children[i]==0) {
            close(gate[1]);close(results[0]);char start;
            if(read(gate[0],&start,1)!=1 || ensure_identity()!=0)_exit(1);
            if(write(results[1],cfg.id,32)!=32)_exit(1);
            _exit(0);
        }
    }
    close(gate[0]);close(results[1]);
    char ready[CHILDREN];memset(ready,'x',sizeof ready);assert(write(gate[1],ready,sizeof ready)==sizeof ready);close(gate[1]);
    char ids[CHILDREN*32];size_t used=0;
    while(used<sizeof ids){ssize_t n=read(results[0],ids+used,sizeof ids-used);assert(n>0);used+=(size_t)n;}
    close(results[0]);
    for(unsigned i=0;i<CHILDREN;i++){int status;assert(waitpid(children[i],&status,0)==children[i]);assert(WIFEXITED(status) && WEXITSTATUS(status)==0);}
    for(unsigned i=1;i<CHILDREN;i++)assert(memcmp(ids,ids+i*32,32)==0);
    assert(ensure_identity()==0);assert(memcmp(cfg.id,ids,32)==0);
    char file[560];snprintf(file,sizeof file,"%s.id",cfg.config);
    /* A malformed existing identity must survive a failed initialization. */
    assert(write_atomic(file,"broken\n",7)==0);cfg.id[0]=0;
    assert(ensure_identity()<0);char *raw=read_file(file);assert(raw && !strcmp(raw,"broken\n"));free(raw);
    unlink(file);snprintf(file,sizeof file,"%s.id.lock",cfg.config);unlink(file);rmdir(dir);
    puts("OK: concurrent initializers share one persistent identity; corruption preserved");
    return 0;
}
