/* Linux CI harness: exercise production SSH helpers against an isolated sshd. */
#include "../src/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 5)
        return 2;
    char config[512], hostfile[512];
    snprintf(config, sizeof config, "%s/client", argv[1]);
    snprintf(hostfile, sizeof hostfile, "%s/host.pub", argv[1]);
    sec_ctx local, remote;
    if (sec_init(&local, config, "00000000000000000000000000000001", "client"))
        return 1;
    if (strcmp(argv[4], "prepare")) {
        snprintf(local.bind_ip, sizeof local.bind_ip, "127.0.0.1");
        int rc =
            access_command(&local, argv[4], "00000000000000000000000000000002", argc - 5, argv + 5);
        sec_free(&local);
        return rc ? 1 : 0;
    }
    snprintf(config, sizeof config, "%s/server", argv[1]);
    if (sec_init(&remote, config, "00000000000000000000000000000002", "server"))
        return 1;
    struct json_object *mine = sec_identity(&local), *peer = sec_identity(&remote);
    if (access_identity(&local, mine))
        return 1;
    char *host = sec_read(hostfile);
    if (!host)
        return 1;
    char *end = strchr(host, ' ');
    if (!end)
        return 1;
    end += 1 + strcspn(end + 1, " \t\r\n");
    *end = 0;
    json_object_object_add(peer, "ssh_client", json_object_new_string(sec_str(mine, "ssh_client")));
    json_object_object_add(peer, "ssh_host", json_object_new_string(host));
    free(host);
    json_object_object_add(peer, "ssh_user", json_object_new_string(argv[2]));
    json_object_object_add(peer, "ssh_port", json_object_new_string(argv[3]));
    if (access_validate(peer) || sec_pin(&local, peer))
        return 1;
    sec_frame frame = {
        .id = "00000000000000000000000000000002", .name = "server", .ip = "127.0.0.1"};
    if (sec_record_endpoint(&local, &frame))
        return 1;
    snprintf(local.bind_ip, sizeof local.bind_ip, "127.0.0.1");
    int result = 0;
    if (!strcmp(argv[4], "prepare")) {
        snprintf(config, sizeof config, "%s/authorized_keys", argv[1]);
        result =
            sec_atomic(config, sec_str(mine, "ssh_client"), strlen(sec_str(mine, "ssh_client")));
    } else
        result = access_command(&local, argv[4], remote.id, argc - 5, argv + 5);
    json_object_put(mine);
    json_object_put(peer);
    sec_free(&local);
    sec_free(&remote);
    return result ? 1 : 0;
}
