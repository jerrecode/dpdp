#define main dpdp_program_main
#include "../src/dpdp.c"
#undef main
#include <assert.h>
int main(void) {
    int receiver = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(receiver >= 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    assert(bind(receiver, (struct sockaddr *)&to, sizeof to) == 0);
    socklen_t length = sizeof to;
    assert(getsockname(receiver, (struct sockaddr *)&to, &length) == 0);
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    cur_ifindex = (int)if_nametoindex("lo");
    assert(cur_ifindex > 0);
    assert(inet_pton(AF_INET, "127.0.0.2", &cur_ip) == 1);
    assert(send_selected("x", 1, &to) == 1);
    struct pollfd pollfd = {.fd = receiver, .events = POLLIN};
    assert(poll(&pollfd, 1, 1000) == 1);
    struct sockaddr_in source = {0};
    length = sizeof source;
    char value;
    assert(recvfrom(receiver, &value, 1, 0, (struct sockaddr *)&source, &length) == 1);
    assert(source.sin_addr.s_addr == cur_ip.s_addr);
    close(fd);
    fd = -1;
    close(receiver);
    puts("OK: unicast sends from the selected source IP via IP_PKTINFO");
    return 0;
}
