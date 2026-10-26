#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <json-c/json.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PEERS 128
#define MAX_FILE 1048576
#define PORT_DEFAULT 47981
#define GROUP "239.255.77.81"
#define MAX_PACKET 256

typedef struct {
    char iface[IFNAMSIZ], name[49], ssid[129], id[33];
    char registry[512], config[512];
    unsigned port, announce_s, expiry_s, offline_s, wrong_s;
    int termux;
} config_t;
typedef struct {
    char id[33], name[49], ip[INET_ADDRSTRLEN];
    uint64_t last_ms;
    time_t last_saved;
    int online, dispatched;
} peer_t;
static config_t cfg;
static peer_t peers[MAX_PEERS];
static unsigned peer_count;
static int fd = -1, cur_ifindex;
static struct in_addr cur_ip;
static volatile sig_atomic_t stopping;
static uint64_t seq_no;
static int debug_mode;

static void stop_handler(int sig) { (void)sig; stopping = 1; }
static uint64_t mono_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000; }
static void message(const char *type, const char *info) { fprintf(stderr, "[dpdp] %s: %s\n", type, info); }
static void copy(char *dst, size_t n, const char *src) { if (n) { snprintf(dst, n, "%s", src ? src : ""); } }
static int valid_label(const char *s, size_t max) {
    size_t n = strlen(s); if (!n || n > max) return 0;
    for (size_t i=0;i<n;i++) if (!(s[i]>='a' && s[i]<='z') && !(s[i]>='A' && s[i]<='Z') && !(s[i]>='0' && s[i]<='9') && s[i]!='-' && s[i]!='_' && s[i]!='.') return 0;
    return 1;
}
static int valid_id(const char *s) {
    if (strlen(s)!=32) return 0;
    for (int i=0;i<32;i++) if (!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) return 0;
    return 1;
}
static int mkdirs(const char *path) {
    char tmp[512]; copy(tmp,sizeof tmp,path);
    for (char *p=tmp+1; *p; p++) if (*p=='/') { *p=0; if (mkdir(tmp,0700)<0 && errno!=EEXIST) return -1; *p='/'; }
    if (mkdir(tmp,0700)<0 && errno!=EEXIST) return -1;
    return 0;
}
static int ensure_parent(const char *path) {
    char buf[512]; copy(buf,sizeof buf,path); char *p=strrchr(buf,'/');
    if (!p) return 0;
    *p=0;
    return mkdirs(buf);
}
static int write_atomic(const char *path, const char *data, size_t len) {
    if (ensure_parent(path)) return -1;
    char temp[550]; if (snprintf(temp,sizeof temp,"%s.tmp.XXXXXX",path)>=(int)sizeof temp) return -1;
    int out = mkstemp(temp); if (out<0) return -1;
    fchmod(out,0600);
    size_t pos=0; while (pos<len) { ssize_t n=write(out,data+pos,len-pos); if (n<0 && errno==EINTR) continue; if (n<=0) break; pos+=(size_t)n; }
    int ok=(pos==len && fsync(out)==0); if (close(out)<0) ok=0;
    if (ok && rename(temp,path)==0) {
        char parent[512]; copy(parent,sizeof parent,path); char *slash=strrchr(parent,'/');
        if (slash) { *slash=0; int d=open(parent,O_RDONLY|O_DIRECTORY); if(d>=0){fsync(d);close(d);} }
        return 0;
    }
    unlink(temp); return -1;
}
static char *read_file(const char *path) {
    int f=open(path,O_RDONLY|O_NOFOLLOW); if (f<0) return NULL;
    struct stat st; if (fstat(f,&st)<0 || st.st_size<0 || st.st_size>MAX_FILE) {close(f); return NULL;}
    char *buf=calloc((size_t)st.st_size+2,1); if (!buf) {close(f);return NULL;}
    size_t pos=0; while (pos<(size_t)st.st_size) { ssize_t n=read(f,buf+pos,(size_t)st.st_size-pos); if (n<0 && errno==EINTR) continue; if(n<=0) break; pos+=(size_t)n; }
    close(f); if(pos!=(size_t)st.st_size){free(buf);return NULL;} return buf;
}
static struct json_object *read_json(const char *path) {
    char *raw=read_file(path); if (!raw) return NULL;
    struct json_tokener *tok=json_tokener_new();
    struct json_object *o=tok?json_tokener_parse_ex(tok,raw,(int)strlen(raw)):NULL;
    if (!tok || json_tokener_get_error(tok)!=json_tokener_success || !o || !json_object_is_type(o,json_type_object)) { if(o)json_object_put(o);o=NULL; }
    if(tok)json_tokener_free(tok);
    free(raw);
    return o;
}
static void set_string(struct json_object *o,const char *key,const char *str) {json_object_object_add(o,key,json_object_new_string(str));}
static void set_bool(struct json_object *o,const char *key,int yes) {json_object_object_add(o,key,json_object_new_boolean(yes));}
static struct json_object *obj_field(struct json_object *o,const char *key) {struct json_object *x=NULL; if(o)json_object_object_get_ex(o,key,&x);return x;}
static const char *str_field(struct json_object *o,const char *key) {struct json_object *v=obj_field(o,key);return v && json_object_is_type(v,json_type_string)?json_object_get_string(v):"";}

/* Registry updates parse the current file on every write. Unknown fields and user-managed
   trust/services fields remain untouched; an advisory lock protects cooperating writers. */
static int sync_registry(peer_t *p) {
    char lockpath[550]; snprintf(lockpath,sizeof lockpath,"%s.lock",cfg.registry);
    if (ensure_parent(cfg.registry)) return -1;
    int lock=open(lockpath,O_CREAT|O_RDWR,0600); if(lock<0)return -1;
    if(flock(lock,LOCK_EX)<0){close(lock);return -1;}
    struct json_object *root=read_json(cfg.registry);
    if(!root) {
        if(access(cfg.registry,F_OK)==0){message("error","registry invalid: refusing to overwrite it");flock(lock,LOCK_UN);close(lock);return -1;}
        root=json_object_new_object();
    }
    if(!root){flock(lock,LOCK_UN);close(lock);return -1;}
    struct json_object *all=obj_field(root,"peers");
    if(!all || !json_object_is_type(all,json_type_object)) {
        if(all){message("error","invalid peers entry");json_object_put(root);flock(lock,LOCK_UN);close(lock);return -1;}
        all=json_object_new_object(); json_object_object_add(root,"peers",all);
    }
    if(p) {
        char key[96]={0}; struct json_object *item=NULL;
        json_object_object_foreach(all,k,v) {if (!strcmp(str_field(v,"id"),p->id)){copy(key,sizeof key,k);break;}}
        if(!key[0]) {
            copy(key,sizeof key,p->name);
            if(obj_field(all,key)) snprintf(key,sizeof key,"%.48s-%.8s",p->name,p->id);
        }
        item=obj_field(all,key);
        /* Keep the reported-name key current while preserving user-owned fields. */
        char desired[96];copy(desired,sizeof desired,p->name);
        struct json_object *collision=obj_field(all,desired);
        if(collision && strcmp(str_field(collision,"id"),p->id))
            snprintf(desired,sizeof desired,"%.48s-%.8s",p->name,p->id);
        if(item && strcmp(key,desired)) {
            json_object_object_add(all,desired,json_object_get(item));
            json_object_object_del(all,key);
            item=obj_field(all,desired);
        }
        if(!item || !json_object_is_type(item,json_type_object)) {
            item=json_object_new_object(); json_object_object_add(all,key,item);
        }
        set_string(item,"id",p->id); set_string(item,"name",p->name); set_string(item,"ip",p->ip);
        set_bool(item,"online",p->online);
        if(p->online) json_object_object_add(item,"last_seen_unix",json_object_new_int64((int64_t)time(NULL)));
        if(!obj_field(item,"trusted")) set_bool(item,"trusted",0);
        if(!obj_field(item,"services")) json_object_object_add(item,"services",json_object_new_array());
    }
    if(!obj_field(root,"schema_version")) json_object_object_add(root,"schema_version",json_object_new_int(1));
    const char *encoded=json_object_to_json_string_ext(root,JSON_C_TO_STRING_PRETTY|JSON_C_TO_STRING_SPACED);
    int ok=encoded && write_atomic(cfg.registry,encoded,strlen(encoded))==0;
    json_object_put(root); flock(lock,LOCK_UN);close(lock); return ok?0:-1;
}
/* Commands are strictly local and require trusted=true; network packets contain no commands. */
static int start_services(peer_t *p) {
    struct json_object *root=read_json(cfg.registry); if(!root) return 0;
    struct json_object *all=obj_field(root,"peers"), *item=NULL;
    if(all && json_object_is_type(all,json_type_object)) {
        json_object_object_foreach(all,k,v){(void)k;if(!strcmp(str_field(v,"id"),p->id)){item=v;break;}}
    }
    if(!item || !json_object_get_boolean(obj_field(item,"trusted"))) {json_object_put(root);return 0;}
    struct json_object *services=obj_field(item,"services");
    int launches=0;
    if(services && json_object_is_type(services,json_type_array)) {
        size_t n=json_object_array_length(services); if(n>16)n=16;
        for(size_t i=0;i<n;i++) {
            struct json_object *s=json_object_array_get_idx(services,i);
            if(!json_object_get_boolean(obj_field(s,"enabled"))) continue;
            const char *cmd=str_field(s,"exec");
            if(cmd[0]!='/' || strlen(cmd)>400 || strchr(cmd,'\n')) continue;
            struct json_object *args=obj_field(s,"args");
            size_t num=args && json_object_is_type(args,json_type_array)?json_object_array_length(args):0;
            if(num>24)continue;
            char *argv[26]={0}; argv[0]=(char*)cmd;
            int valid=1;
            for(size_t j=0;j<num;j++) {
                struct json_object *v=json_object_array_get_idx(args,j);
                if(!json_object_is_type(v,json_type_string) || strlen(json_object_get_string(v))>512){valid=0;break;}
                argv[j+1]=(char*)json_object_get_string(v);
            }
            if(!valid)continue;
            pid_t pid=fork();
            if(pid==0){
                setenv("DPDP_PEER_ID",p->id,1);setenv("DPDP_PEER_NAME",p->name,1);
                setenv("DPDP_PEER_IP",p->ip,1);
                char port[12];snprintf(port,sizeof port,"%u",cfg.port);setenv("DPDP_DISCOVERY_PORT",port,1);
                execv(cmd,argv);_exit(127);
            }
            if(pid>0){launches++;message("service started",cmd);}
        }
    }
    json_object_put(root); return launches;
}
static int ensure_identity(void) {
    char file[560];snprintf(file,sizeof file,"%s.id",cfg.config);
    char *existing=read_file(file);
    if(existing){ char *nl=strchr(existing,'\n');if(nl)*nl=0;
        if(valid_id(existing))copy(cfg.id,sizeof cfg.id,existing);
        free(existing);if(cfg.id[0])return 0;
        message("error","invalid existing identity; refusing to replace");return -1;
    }
    unsigned char b[16]; int randomfd=open("/dev/urandom",O_RDONLY); if(randomfd<0)return -1;
    ssize_t got=read(randomfd,b,sizeof b);close(randomfd);if(got!=(ssize_t)sizeof b)return -1;
    for(int i=0;i<16;i++)snprintf(cfg.id+i*2,3,"%02x",b[i]);
    char s[40];snprintf(s,sizeof s,"%s\n",cfg.id);
    if(write_atomic(file,s,strlen(s))<0)return -1;
    return 0;
}
static void defaults(void) {
    memset(&cfg,0,sizeof cfg);
    const char *home=getenv("HOME");if(!home)home=".";
    const char *xdg=getenv("XDG_CONFIG_HOME"), *state=getenv("XDG_STATE_HOME");
    if(xdg && *xdg)snprintf(cfg.config,sizeof cfg.config,"%s/dpdp/config",xdg);
    else snprintf(cfg.config,sizeof cfg.config,"%s/.config/dpdp/config",home);
    if(state && *state)snprintf(cfg.registry,sizeof cfg.registry,"%s/dpdp/peers.json",state);
    else snprintf(cfg.registry,sizeof cfg.registry,"%s/.local/state/dpdp/peers.json",home);
    char host[128]="node";gethostname(host,sizeof host-1);
    for(char *p=host;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='-'||*p=='_'||*p=='.'))*p='-';
    copy(cfg.name,sizeof cfg.name,host);
    copy(cfg.iface,sizeof cfg.iface,getenv("PREFIX") && strstr(getenv("PREFIX"),"com.termux")?"wlan0":"");
    cfg.termux=getenv("PREFIX") && strstr(getenv("PREFIX"),"com.termux")!=NULL;
    cfg.port=PORT_DEFAULT;cfg.announce_s=15;cfg.expiry_s=70;cfg.offline_s=60;cfg.wrong_s=15;
}
static void load_config(const char *file) {
    FILE *f=fopen(file,"r");if(!f)return;
    char line[800];while(fgets(line,sizeof line,f)) {
        char *s=line;while(*s==' '||*s=='\t')s++;
        if(*s=='#'||*s=='\n'||!*s)continue;
        char *eq=strchr(s,'=');if(!eq)continue;*eq++=0;
        char *end=s+strlen(s);while(end>s && (end[-1]==' '||end[-1]=='\t'))*--end=0;
        eq[strcspn(eq,"\r\n")]=0;
        if(!strcmp(s,"interface"))copy(cfg.iface,sizeof cfg.iface,eq);
        else if(!strcmp(s,"name"))copy(cfg.name,sizeof cfg.name,eq);
        else if(!strcmp(s,"expected_ssid"))copy(cfg.ssid,sizeof cfg.ssid,eq);
        else if(!strcmp(s,"registry"))copy(cfg.registry,sizeof cfg.registry,eq);
        else if(!strcmp(s,"port"))cfg.port=(unsigned)strtoul(eq,NULL,10);
        else if(!strcmp(s,"announce_seconds"))cfg.announce_s=(unsigned)strtoul(eq,NULL,10);
        else if(!strcmp(s,"expiry_seconds"))cfg.expiry_s=(unsigned)strtoul(eq,NULL,10);
        else if(!strcmp(s,"sleep_no_wifi_seconds"))cfg.offline_s=(unsigned)strtoul(eq,NULL,10);
        else if(!strcmp(s,"sleep_wrong_wifi_seconds"))cfg.wrong_s=(unsigned)strtoul(eq,NULL,10);
    }
    fclose(f);
}
static int interface_address(const char *name,struct in_addr *addr) {
    struct ifaddrs *all=NULL;if(getifaddrs(&all)<0)return -1;
    int found=-1;
    for(struct ifaddrs *p=all;p;p=p->ifa_next)if(p->ifa_addr && p->ifa_addr->sa_family==AF_INET &&
        (p->ifa_flags & IFF_UP) && (p->ifa_flags & IFF_MULTICAST) && !strcmp(p->ifa_name,name)) {
        struct in_addr a=((struct sockaddr_in*)p->ifa_addr)->sin_addr;
        if((ntohl(a.s_addr)>>24)==127 && strcmp(name,"lo"))continue;
        *addr=a;found=0;break;
    }
    freeifaddrs(all);return found;
}
/* Returns 0 when expected network present, 1 for no Wi-Fi, 2 for different Wi-Fi,
   3 for unavailable/unverifiable Android API. Never leak discovery to unverified SSIDs. */
static int phone_network(void) {
    if(!cfg.termux || !cfg.ssid[0]) return 0;
    FILE *f=popen("timeout 4 termux-wifi-connectioninfo 2>/dev/null","r");if(!f)return 3;
    char buf[8192]={0};size_t n=fread(buf,1,sizeof buf-1,f);int rc=pclose(f);
    if(!n || rc!=0)return 3;
    struct json_object *j=json_tokener_parse(buf);if(!j)return 3;
    const char *ssid=str_field(j,"ssid");
    int ans= !ssid[0] || !strcmp(ssid,"<unknown ssid>") || !strcmp(ssid,"unknown ssid")?1:strcmp(ssid,cfg.ssid)?2:0;
    json_object_put(j);return ans;
}
static void close_socket(void){if(fd>=0)close(fd);fd=-1;cur_ifindex=0;memset(&cur_ip,0,sizeof cur_ip);}
static int open_socket(struct in_addr ip,int ifindex){
    int s=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(s<0)return -1;
    int one=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
#ifdef SO_REUSEPORT
    setsockopt(s,SOL_SOCKET,SO_REUSEPORT,&one,sizeof one);
#endif
    if(setsockopt(s,IPPROTO_IP,IP_PKTINFO,&one,sizeof one)<0){close(s);return -1;}
    struct sockaddr_in bindaddr={.sin_family=AF_INET,.sin_port=htons((uint16_t)cfg.port),.sin_addr={.s_addr=INADDR_ANY}};
    if(bind(s,(struct sockaddr*)&bindaddr,sizeof bindaddr)<0){close(s);return -1;}
    struct ip_mreq member={.imr_multiaddr={.s_addr=inet_addr(GROUP)},.imr_interface=ip};
    if(setsockopt(s,IPPROTO_IP,IP_ADD_MEMBERSHIP,&member,sizeof member)<0 ||
       setsockopt(s,IPPROTO_IP,IP_MULTICAST_IF,&ip,sizeof ip)<0){close(s);return -1;}
    unsigned char ttl=1;setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof ttl);
    fd=s;cur_ifindex=ifindex;cur_ip=ip;return 0;
}
static void send_packet(char type,const struct sockaddr_in *dest) {
    if(fd<0)return;
    char buf[MAX_PACKET];
    int n=snprintf(buf,sizeof buf,"DPDP/1|%c|%s|%s|%llu",type,cfg.id,cfg.name,(unsigned long long)++seq_no);
    if(n<=0 || n>=(int)sizeof buf)return;
    struct sockaddr_in to={.sin_family=AF_INET,.sin_port=htons((uint16_t)cfg.port)};
    if(dest)to=*dest;else inet_pton(AF_INET,GROUP,&to.sin_addr);
    if(sendto(fd,buf,(size_t)n,0,(struct sockaddr*)&to,sizeof to)<0 && debug_mode)perror("sendto");
}
static int parse_packet(char *buf,size_t n,char *kind,char id[33],char name[49]) {
    if(n<45 || n>=MAX_PACKET)return -1;
    buf[n]=0;
    char *parts[5],*save=NULL,*p=strtok_r(buf,"|",&save);
    for(int i=0;i<5;i++){if(!p)return -1;parts[i]=p;p=strtok_r(NULL,"|",&save);}
    if(p||strcmp(parts[0],"DPDP/1") || strlen(parts[1])!=1 || (parts[1][0]!='A' && parts[1][0]!='Q') ||
       !valid_id(parts[2]) || !valid_label(parts[3],48) || !parts[4][0])return -1;
    for(char *q=parts[4];*q;q++)if(*q<'0'||*q>'9')return -1;
    *kind=parts[1][0];copy(id,33,parts[2]);copy(name,49,parts[3]);return 0;
}
static peer_t *upsert(const char *id,const char *name,const char *ip) {
    peer_t *p=NULL;
    for(unsigned i=0;i<peer_count;i++)if(!strcmp(peers[i].id,id)){p=&peers[i];break;}
    if(!p){if(peer_count>=MAX_PEERS)return NULL;p=&peers[peer_count++];memset(p,0,sizeof *p);copy(p->id,sizeof p->id,id);}
    int changed=!p->online || strcmp(p->name,name) || strcmp(p->ip,ip);
    if(strcmp(p->ip,ip))p->dispatched=0;
    copy(p->name,sizeof p->name,name);copy(p->ip,sizeof p->ip,ip);
    p->online=1;p->last_ms=mono_ms();
    time_t now=time(NULL);
    if(changed || now-p->last_saved>=30){if(sync_registry(p))message("warning","could not persist peer state");else p->last_saved=now;}
    if(changed)message("peer online",name);
    if(!p->dispatched)if(start_services(p)>0)p->dispatched=1;
    return p;
}
static void recv_one(void) {
    char buf[MAX_PACKET+1],ctrl[128];struct sockaddr_in sender={0};
    struct iovec iov={.iov_base=buf,.iov_len=MAX_PACKET};
    struct msghdr msg={.msg_name=&sender,.msg_namelen=sizeof sender,.msg_iov=&iov,.msg_iovlen=1,.msg_control=ctrl,.msg_controllen=sizeof ctrl};
    ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT);
    if(n<=0 || (msg.msg_flags&MSG_TRUNC))return;
    int seen_if=0;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c))
        if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO) {struct in_pktinfo *pi=(struct in_pktinfo*)CMSG_DATA(c);seen_if=pi->ipi_ifindex;}
    if(seen_if!=cur_ifindex)return;
    char id[33],name[49],kind;
    if(parse_packet(buf,(size_t)n,&kind,id,name))return;
    if(!strcmp(id,cfg.id))return;
    char ip[INET_ADDRSTRLEN];if(!inet_ntop(AF_INET,&sender.sin_addr,ip,sizeof ip))return;
    /* Sender address is from the received packet, never from untrusted advertised data. */
    upsert(id,name,ip);
    if(kind=='Q')send_packet('A',&sender);
}
static void mark_lost(void) {
    uint64_t now=mono_ms();
    for(unsigned i=0;i<peer_count;i++) {
        peer_t *p=&peers[i];if(p->online && now-p->last_ms>(uint64_t)cfg.expiry_s*1000) {
            p->online=0;p->dispatched=0;
            sync_registry(p);message("peer offline",p->name);
        }
    }
}
static void load_old_peers(void){
    struct json_object *root=read_json(cfg.registry),*all=obj_field(root,"peers");
    if(all && json_object_is_type(all,json_type_object)) {
        json_object_object_foreach(all,k,v) {
            (void)k;const char *id=str_field(v,"id"),*name=str_field(v,"name"),*ip=str_field(v,"ip");
            if(peer_count>=MAX_PEERS)break;
            struct in_addr addr;
            if(!valid_id(id)||!valid_label(name,48)||inet_pton(AF_INET,ip,&addr)!=1)continue;
            peer_t *p=&peers[peer_count++];copy(p->id,sizeof p->id,id);copy(p->name,sizeof p->name,name);copy(p->ip,sizeof p->ip,ip);
            p->online=0;p->dispatched=0;
        }
    }
    if(root)json_object_put(root);
}
static void usage(void){puts("DPDP - C IPv4 LAN peer discovery\nUsage: dpdp run [--config FILE] [--interface IF] [--debug]\n       dpdp init [--config FILE]\n       dpdp status [--config FILE]\n       dpdp help\nConfig: interface, name, expected_ssid, registry, port, announce_seconds, expiry_seconds, sleep_no_wifi_seconds, sleep_wrong_wifi_seconds");}
int main(int argc,char **argv) {
    defaults(); const char *action=argc>1?argv[1]:"help",*override_if=NULL;
    for(int i=2;i<argc;i++) {
        if(!strcmp(argv[i],"--config") && i+1<argc)copy(cfg.config,sizeof cfg.config,argv[++i]);
        else if(!strcmp(argv[i],"--interface") && i+1<argc)override_if=argv[++i];
        else if(!strcmp(argv[i],"--debug"))debug_mode=1;
        else {usage();return 2;}
    }
    load_config(cfg.config);if(override_if)copy(cfg.iface,sizeof cfg.iface,override_if);
    if(!strcmp(action,"help") || !strcmp(action,"--help")){usage();return 0;}
    if(!strcmp(action,"status")) {
        struct json_object *root=read_json(cfg.registry);
        if(!root){message("error","no valid peers registry");return 1;}
        puts(json_object_to_json_string_ext(root,JSON_C_TO_STRING_PRETTY));json_object_put(root);return 0;
    }
    if(strcmp(action,"init") && strcmp(action,"run")){usage();return 2;}
    if(!valid_label(cfg.name,48) || cfg.port<1024 || cfg.port>65535 || cfg.announce_s<2 || cfg.announce_s>3600 || cfg.expiry_s<=cfg.announce_s || cfg.expiry_s>86400 || cfg.offline_s<5 || cfg.offline_s>3600 || cfg.wrong_s<5 || cfg.wrong_s>3600) {
        message("error","invalid configuration value");return 2;
    }
    if(ensure_identity() || sync_registry(NULL)){message("error","could not initialize identity or registry");return 1;}
    if(!strcmp(action,"init")){printf("identity: %s\nregistry: %s\n",cfg.id,cfg.registry);return 0;}
    if(!cfg.iface[0] || if_nametoindex(cfg.iface)==0){message("warning","interface absent; daemon will poll until it appears");}
    load_old_peers();
    for(unsigned i=0;i<peer_count;i++)sync_registry(&peers[i]);
    signal(SIGINT,stop_handler);signal(SIGTERM,stop_handler);signal(SIGCHLD,SIG_DFL);
    message("started",cfg.name);
    uint64_t next_check=0,next_announce=0;int state=-1;
    while(!stopping) {
        uint64_t now=mono_ms();
        if(now>=next_check) {
            int net=phone_network();struct in_addr ip={0};int idx=(int)if_nametoindex(cfg.iface);
            if(net==0 && (!idx || interface_address(cfg.iface,&ip)))net=1;
            if(net || (fd>=0 && (idx!=cur_ifindex || ip.s_addr!=cur_ip.s_addr)))close_socket();
            int opened=0;
            if(!net && fd<0) {if(open_socket(ip,idx)<0)net=1;else opened=1;}
            if(net!=state){message("network state",net==0?"connected":net==1?"no Wi-Fi/IP":net==2?"wrong SSID":"Termux Wi-Fi API unavailable");state=net;}
            unsigned wait=net==1?cfg.offline_s:net?cfg.wrong_s:5;
            next_check=mono_ms()+(uint64_t)wait*1000;
            if(opened) next_announce=mono_ms();
        }
        if(fd>=0 && now>=next_announce){send_packet('Q',NULL);send_packet('A',NULL);next_announce=mono_ms()+(uint64_t)cfg.announce_s*1000;}
        mark_lost();
        if(fd>=0){
            struct pollfd pfd={.fd=fd,.events=POLLIN};
            int rc=poll(&pfd,1,1000);
            if(rc>0 && (pfd.revents&POLLIN))recv_one();
        } else {
            /* Truly sleep through the disconnected interval instead of waking
               every second. SIGINT/SIGTERM interrupt this sleep promptly. */
            uint64_t current=mono_ms();
            int delay=next_check>current?(int)(next_check-current):0;
            poll(NULL,0,delay);
        }
        /* Service hooks are child processes. Reap them only outside popen/pclose,
           so the Termux API subprocess still has a waitable exit status. */
        while(waitpid(-1,NULL,WNOHANG)>0) {}
    }
    close_socket();message("stopped",cfg.name);return 0;
}
