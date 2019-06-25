#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <libssh/libssh.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <signal.h>
#include <pwd.h>

#define SSH_SELECT
// #define SELECT

#define DIE(msg) perror(msg); return -1;
#define SHOW(msg, var) if(Flag.DEBUG == 1) printf("%s %s\n", msg, var);

const char *password = NULL;
char private_key_path[100];
const char *server_ip = "172.17.0.2";
unsigned int server_port = 22;
const char *local_listenip = NULL;
unsigned int local_listenport = 2222;
const char *remote_desthost = "127.0.0.1";
unsigned int remote_destport = 8000;
int32_t listensock;

struct{
        unsigned int DEBUG : 1;
        unsigned int EXIT : 1;
        unsigned int LSOCK : 1;
}Flag;

typedef struct{
        ssh_session Session;
        char *Username;
        char *LHost;
        char *RHost;
        char *SHost;
        int SPort;
        int LPort;
        int RPort;
}Info_t;

char *GetUsername() {
        struct passwd *p = getpwuid(getuid());
        return p->pw_name;
}

int verify_knownhost(ssh_session session) {
        enum ssh_known_hosts_e state;
        unsigned char *hash = NULL;
        ssh_key pubkey = NULL;
        size_t hlen;
        char buf[10];
        char *hexa;
        char *p;
        int cmp;
        int rc;

        if ((rc = ssh_get_server_publickey(session, &pubkey)) < 0) {
                DIE("ssh_get_server_publickey()");
        }else

        if((rc = ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash,&hlen)) < 0) {
                ssh_key_free(pubkey);
                DIE("ssh_get_publickey_hash()");
        }else{
                SHOW("ssh_get_publickey_hash", "success");
        }

        ssh_key_free(pubkey);

        state = ssh_session_is_known_server(session);

        switch (state) {
                case SSH_KNOWN_HOSTS_OK:
                /* OK */
                break;
                case SSH_KNOWN_HOSTS_CHANGED:
                    fprintf(stderr, "Host key for server changed: it is now:\n");
                    ssh_print_hexa("Public key hash", hash, hlen);
                    fprintf(stderr, "For security reasons, connection will be stopped\n");
                    ssh_clean_pubkey_hash(&hash);
                    return -1;
                case SSH_KNOWN_HOSTS_OTHER:
                    fprintf(stderr, "The host key for this server was not found but an other"
                            "type of key exists.\n");
                    fprintf(stderr, "An attacker might change the default server key to"
                            "confuse your client into thinking the key does not exist\n");
                    ssh_clean_pubkey_hash(&hash);
                    return -1;
                case SSH_KNOWN_HOSTS_NOT_FOUND:
                    fprintf(stderr, "Could not find known host file.\n");
                    fprintf(stderr, "If you accept the host key here, the file will be"
                            "automatically created.\n");
                    /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
                case SSH_KNOWN_HOSTS_UNKNOWN:
                    hexa = ssh_get_hexa(hash, hlen);
                    fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
                    fprintf(stderr, "Public key hash: %s\n", hexa);
                    ssh_string_free_char(hexa);
                    ssh_clean_pubkey_hash(&hash);
                    p = fgets(buf, sizeof(buf), stdin);
                    if (p == NULL) {
                        return -1;
                    }
                    cmp = strncasecmp(buf, "yes", 3);
                    if (cmp != 0) {
                        return -1;
                    }
                    rc = ssh_session_update_known_hosts(session);
                    if (rc < 0) {
                        fprintf(stderr, "Error %s\n", strerror(errno));
                        return -1;
                    }
                    break;
                case SSH_KNOWN_HOSTS_ERROR:
                    fprintf(stderr, "Error %s", ssh_get_error(session));
                    ssh_clean_pubkey_hash(&hash);
                    return -1;
        }

        ssh_clean_pubkey_hash(&hash);

        return 0;
}

int authenticate_password(ssh_session session) {
        int rc;

        if((rc = ssh_userauth_password(session, NULL, password)) == SSH_AUTH_ERROR) {
                DIE("ssh_userauth_password failed");
        }else{
                SHOW("ssh_userauth_password", "success");
        }

        return 0;
}

int authenticate_pubkey(ssh_session session) {
        int rc;
        ssh_key pubkey = NULL;
	ssh_key prikey = NULL;
        char *priv_key;

        /* Set user home directory */
        sprintf(priv_key, "%s%s", getenv("HOME"), "/.ssh/id_rsa");


        if((rc = ssh_pki_import_privkey_file(priv_key, NULL, NULL, NULL, &prikey)) != SSH_OK ) {
                DIE("ssh_pki_import_privkey_file()");
        }else{
                SHOW("ssh_pki_import_privkey_file", "success");
        }

        if((rc = ssh_pki_export_privkey_to_pubkey(prikey, &pubkey)) != SSH_OK ) {
                ssh_key_free(prikey);
                DIE("ssh_pki_export_privkey_to_pubkey()");
        }else{
                SHOW("ssh_pki_export_privkey_to_pubkey", "success");
        }

        if((rc = ssh_userauth_try_publickey(session, NULL, pubkey)) != SSH_AUTH_SUCCESS) {
                ssh_key_free(pubkey);
                ssh_key_free(prikey);
                DIE("ssh_userauth_try_publickey()");
        }else{
                SHOW("ssh_userauth_try_publickey", "success");
        }

        if((rc = ssh_userauth_publickey(session, NULL, prikey)) != SSH_AUTH_SUCCESS) {
                ssh_key_free(pubkey);
                ssh_key_free(prikey);
                DIE("ssh_userauth_publickey()");
        }else{
                SHOW("ssh_userauth_publickey", "success");
        }

        ssh_key_free(pubkey);
        ssh_key_free(prikey);

        return 0;
}

int authenticate_agent(ssh_session session) {
        int rc;

        rc = ssh_userauth_agent(session, NULL);
        switch(rc) {
                case SSH_AUTH_SUCCESS:
                        return 1;
                case SSH_AUTH_DENIED:
                        SHOW("SSH_AUTH", "DENIED");
                        break;
                case SSH_AUTH_PARTIAL:
                        SHOW("SSH_AUTH", "PARTIAL");
                        break;
                case SSH_AUTH_AGAIN:
                        SHOW("SSH_AUTH", "AGAIN");
                        break;
        }
        return -1;
}

int connect_server(Info_t *Data) {
        int rc;
        int verbosity = SSH_LOG_PROTOCOL;

        /* Set ssh options */
        ssh_options_set(Data->Session, SSH_OPTIONS_HOST, Data->SHost);
	ssh_options_set(Data->Session, SSH_OPTIONS_PORT, &Data->SPort);
	ssh_options_set(Data->Session, SSH_OPTIONS_USER, Data->Username);
	ssh_options_set(Data->Session, SSH_OPTIONS_KNOWNHOSTS, "~/.ssh/known_hosts");
        if(Flag.DEBUG == 1) {
                ssh_options_set(Data->Session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
        }

        /* Connect to server */
        if((rc = ssh_connect(Data->Session)) != SSH_OK) {
                DIE("ssh_connect()");
        }else{
                SHOW("ssh connect", "success");
        }

        /* Verify the server's identity with known_hosts keyfile */
        if (verify_knownhost(Data->Session) < 0) {
                ssh_disconnect(Data->Session);
                ssh_free(Data->Session);
                DIE("verify_knownhost()");
        }else{
                SHOW("verify_knownhost", "success");
        }

        /* authenticate with agent */
        if(authenticate_agent(Data->Session) > 0) {
                SHOW("authenticate_agent", "success");
                return 0;
        }
        /* authenticate with pubkey */
        if (authenticate_pubkey(Data->Session) > 0) {
                SHOW("authenticate_pubkey", "success");
                return 0;
        }
        /* authenticate with password */
        if (authenticate_password(Data->Session) > 0) {
                SHOW("authenticate_password", "success");
                return 0;
        }
}

char *GetLocalIP() {
        char host[256];
        char *IP;
        struct hostent *host_entry;
        int hostname;
        hostname = gethostname(host, sizeof(host));
        host_entry = gethostbyname(host);
        IP = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));
        return IP;
}

int32_t open_listening_port(Info_t *Data) {
        struct sockaddr_in sin;
        int sockopt = 1;

        /* Get a socket descriptor */
        if((listensock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
                DIE("Socket()");
        }else{
                /* Print forwarding condition */
                fprintf(stderr, "Forwarding connection from %s:%d here to remote %s:%d\n",
                        Data->LHost, Data->LPort, Data->RHost, Data->RPort);
        }

        /* Allow socket descriptor to be reusable */
        if(-1 == setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt))) {
                close(listensock);
                DIE("setsockopt()");
        }else{
                SHOW("Setsockopt listen socket...", "success");
        }

        /* bind to an address */
        bzero((char *) &sin, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(Data->LPort);
        sin.sin_addr.s_addr = inet_addr(Data->LHost);
        if(INADDR_NONE == sin.sin_addr.s_addr) {
                close(listensock);
                DIE("inet_addr");
        }else{
                SHOW("local_listenip:", Data->LHost);
        }

        /* Bind to get unique name for the socket */
        if(-1 == bind(listensock, (struct sockaddr *)&sin, sizeof(sin))) {
                close(listensock);
                DIE("bind()");
        }else{
                SHOW("listen socket bind...", "success");
        }

        /* Listen to 2 incoming queued */
        if(-1 == listen(listensock, 2)) {
                close(listensock);
                DIE("listen()");
        }else{
                Flag.LSOCK = 1;
                fprintf(stderr, "Waiting for TCP connection on %s:%d...\n",
                        inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
        }

        return listensock;

}

void forward_traffic(ssh_channel channel, int sock) {
        int32_t size_recv = 0, nwritten = 0, nread = 0;
        char buf[65535] = {0};

        SHOW("Forward Traffic Method:", "Socket");

        while(!ssh_channel_is_eof(channel)) {
                if((size_recv = recv(sock, buf, sizeof(buf), MSG_DONTWAIT) ) < 0) {
                        if((nread = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 0)) > 0) {
                                if(write(sock, buf, nread) < 0) {
                                        perror("Error writing to socket");
                                        goto cleanup;
                                }
                        }
                }else if (!size_recv) {
                        puts("Local client disconnected, exiting");
                        goto cleanup;
                }
                nwritten = ssh_channel_write(channel, buf, size_recv);
                if (size_recv != nwritten) {
                        ssh_channel_free(channel);
                        goto cleanup;
                }
        }

        cleanup:
        ssh_channel_free(channel);
        close(sock);
}

void forward_traffic_select(ssh_channel channel, int sock) {
        int32_t size_recv = 0, nwritten = 0, nread = 0;
        char buf[65535] = {0};
        struct timeval tv;
        fd_set fds;
        int rc;

        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        SHOW("Forward Traffic Method:", "Select");

        rc = select(sock + 1, &fds, NULL, NULL, &tv);

        if(rc && FD_ISSET(sock, &fds)) {
                if((size_recv = recv(sock, buf, sizeof(buf), MSG_DONTWAIT) ) > 0) {
                        printf("size_recv: %d\n", size_recv);
                        nwritten = ssh_channel_write(channel, buf, size_recv);
                        if (size_recv != nwritten) {
                                perror("Error writing to channel");
                                goto cleanup;
                        }
                }else if(!size_recv) {
                        puts("Local client disconnected, exiting");
                        goto cleanup;
                }else{
                        puts("Receiving error");
                        goto cleanup;
                }
        }
        while(Flag.EXIT) {
                if((nread = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 0)) > 0) {
                        printf("nread: %d\n", nread);
                        if(write(sock, buf, nread) < 0) {
                                perror("Error writing to socket");
                                goto cleanup;
                        }
                }
                if(ssh_channel_is_eof(channel)) {
                        goto cleanup;
                }
        }

        cleanup:
        ssh_channel_free(channel);
        close(sock);
}

void forward_traffic_ssh_select(ssh_session session, ssh_channel channel, int sock) {
        int32_t size_recv = 0, nwritten = 0, maxfd;
        ssh_channel in_channels[2], out_channels[2];
        char buf[65535] = {0};
        struct timeval tv;
        fd_set fds;
        int rc;

        SHOW("Forward Traffic Method:", "SSH_Select");

        while(!ssh_channel_is_eof(channel)) {
                do {
                        in_channels[0] = channel;
                        in_channels[1] = NULL;
                        FD_ZERO(&fds);
                        FD_SET(ssh_get_fd(session), &fds);
                        FD_SET(sock, &fds);
                        maxfd = sock + ssh_get_fd(session) + 1;
                        tv.tv_sec = 2;  // 2 second timeout
                        tv.tv_usec = 0;

                        rc = ssh_select(in_channels, out_channels, maxfd, &fds, &tv);

                        if(rc==EINTR) continue;

                        /* Checking any data coming from socket */
                        if (FD_ISSET(sock, &fds)) {
                                if((size_recv = recv(sock, buf, sizeof(buf), MSG_DONTWAIT) ) > 0) {
                                        if((nwritten = ssh_channel_write(channel, buf, size_recv)) < 0) {
                                                perror("Error writing to channel");
                                                goto cleanup;
                                        }
                                }
                        }

                        /* Checking any data coming from server thru in_channels[0] */
                        if (in_channels[0] != NULL) {
                                size_recv = ssh_channel_read(channel, buf, sizeof(buf), 0);
                                if(size_recv > 0) {
                                        if((nwritten = write(sock, buf, size_recv)) < 0) {
                                                perror("Error writing to socket");
                                                goto cleanup;
                                        }
                                }
                        }
                } while (rc == SSH_EINTR || rc == SSH_ERROR);
        }

        cleanup:
        ssh_channel_free(channel);
        close(sock);
}

int accept_connection(Info_t *Data, int listensock) {
        int32_t forwardsock;
        struct sockaddr_in sin;
        socklen_t sinlen;
        ssh_channel forwarding_channel;

        /* Accept incoming socket */
        bzero((char *) &sin, sizeof(struct sockaddr_in));
        sinlen = sizeof(sin);
        if((forwardsock = accept(listensock, (struct sockaddr *)&sin, &sinlen)) < 0) {
                DIE("forwardsock accept error");
        }else{
                SHOW("forwardsock accept...", "success")
                /* Print forwarding condition */
                fprintf(stderr, "Forwarding connection from %s:%d here to remote %s:%d\n",
                        Data->LHost, Data->LPort, Data->RHost, Data->RPort);
        }

        /* Create forwarding channel */
        if((forwarding_channel = ssh_channel_new(Data->Session)) == NULL) {
                DIE("Initialize forwarding_channel failed");
        }else{
                SHOW("Initialize forwarding_channel...", "success");
        }

        /* Open forwarding channel */
        if(SSH_OK != ssh_channel_open_forward(forwarding_channel, Data->RHost,
                Data->RPort, Data->LHost, Data->LPort))
        {
                DIE("Open forwarding_channel failed");
        }else{
                SHOW("Open forwarding_channel...", "success");
        }

#ifdef SSH_SELECT
        forward_traffic_ssh_select(Data->Session, forwarding_channel, forwardsock);
#elif defined(SELECT)
        forward_traffic_select(forwarding_channel, forwardsock);
#else
        forward_traffic(forwarding_channel, forwardsock);
#endif

        return 0;
}

void parse_arguments(int argc, char *argv[], Info_t *Data) {
        int opt;
        static char usage[] = "usage: %s [-d debug] [-l local:port] [-r remote:port] [-s server:port]\n";

        Flag.DEBUG = 0;
        Flag.EXIT = 1;
        Flag.LSOCK = 0;

        Data->RHost = strdup(remote_desthost);
        Data->RPort = remote_destport;

        Data->LHost = GetLocalIP();
        Data->LPort = local_listenport;

        Data->SHost = strdup(server_ip);
        Data->SPort = server_port;

        Data->Username = GetUsername();

        while((opt = getopt(argc, argv, "dr:l:s:u:")) != -1) {
                switch(opt) {
                        case 'd':
                                Flag.DEBUG = 1;
                                break;
                        case 'r':
                                sscanf(optarg, "%[^:]:%d", Data->RHost, &Data->RPort);
                                break;
                        case 'l':
                                sscanf(optarg, "%[^:]:%d", Data->LHost, &Data->LPort);
                                break;
                        case 's':
                                sscanf(optarg, "%[^:]:%d", Data->SHost, &Data->SPort);
                                break;
                        case 'u':
                                strcpy(Data->Username, optarg);
                                break;
                        case '?':
                                fprintf(stderr, usage, argv[0]);
                                free(Data->RHost);
                                free(Data->SHost);
                                exit(1);

                }
        }
}

void sigintHandler(int sig_num) {
        signal(SIGINT, sigintHandler);
        Flag.EXIT = 0;
        close(listensock);
}

int main(int argc, char *argv[]) {
        Info_t Data;
        int32_t listensock;
	int rc;

        /* parse arguments */
        parse_arguments(argc, argv, &Data);

        signal(SIGINT, sigintHandler);

        /* Open ssh session */
	if ((Data.Session = ssh_new()) == NULL) {
                SHOW("Initialize ssh session...", "failed");
                goto exit;
        }else{
                SHOW("Initialize ssh session...", "success");
        }

        /* connect to host server or die */
        if((rc = connect_server(&Data)) < 0) {
                goto exit;
        }

        /* open listen socket */
        if((listensock = open_listening_port(&Data)) < 0) {
                goto exit;
        }

        while(Flag.EXIT) {
                accept_connection(&Data, listensock);
        }

        exit:
        printf("clean up\n");
        free(Data.RHost);
        free(Data.SHost);
        ssh_disconnect(Data.Session);
        ssh_free(Data.Session);
        if(Flag.LSOCK) close(listensock);

        return 0;
}
