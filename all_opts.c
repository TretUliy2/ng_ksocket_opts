#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <netgraph.h>
#include <netgraph/ng_ksocket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

union val {
    int i_val;
    long l_val;
    struct linger linger_val;
    struct timeval timeval_val;
} val;

static char *sock_str_flag(union val *, int);
static char *sock_str_int(union val *, int);
static char *sock_str_linger(union val *, int);
static char *sock_str_timeval(union val *, int);


static char stress[128];

struct sock_opts {
    const char *opt_str;
    int opt_level;
    int opt_name;
    char *(*opt_val_str)(union val *, int);
} sock_opts[] ={
    {"SO_BROADCAST", SOL_SOCKET, SO_BROADCAST, sock_str_flag},
    {"SO_DEBUG", SOL_SOCKET, SO_DEBUG, sock_str_flag},
    {"SO_DONTROUTE", SOL_SOCKET, SO_DONTROUTE, sock_str_flag},
    {"SO_ERROR", SOL_SOCKET, SO_ERROR, sock_str_int},
    {"SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE, sock_str_flag},
    {"SO_LINGER", SOL_SOCKET, SO_LINGER, sock_str_linger},
    {"SO_OOBINLINE", SOL_SOCKET, SO_OOBINLINE, sock_str_flag},
    {"SO_RCVBUF", SOL_SOCKET, SO_RCVBUF, sock_str_int},
    {"SO_SNDBUF", SOL_SOCKET, SO_SNDBUF, sock_str_int},
    {"SO_RCVLOWAT", SOL_SOCKET, SO_RCVLOWAT, sock_str_int},
    {"SO_SNDLOWAT", SOL_SOCKET, SO_SNDLOWAT, sock_str_int},
    {"SO_RCVTIMEO", SOL_SOCKET, SO_RCVTIMEO, sock_str_timeval},
    {"SO_SNDTIMEO", SOL_SOCKET, SO_SNDTIMEO, sock_str_timeval},
    {"SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR, sock_str_flag},
#ifdef SO_REUSEPORT
    {"SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT, sock_str_flag},
#else 
    {"SO_REUSEPORT", 0, 0, NULL},
#endif
    {"SO_TYPE", SOL_SOCKET, SO_TYPE, sock_str_int},
    {"IP_TOS", IPPROTO_IP, IP_TOS, sock_str_int},
    {"IP_TTL", IPPROTO_IP, IP_TTL, sock_str_int},
    {"TCP_MAXSEG", IPPROTO_TCP, TCP_MAXSEG, sock_str_int},
    {"TCP_NODELAY", IPPROTO_TCP, TCP_NODELAY, sock_str_flag},
    {NULL, 0, 0, NULL}
};

static int csock, dsock;

int get_sockopt(void);
int get_ksockopts_all ( char path[NG_PATHSIZ] );
int get_ksock_opt( char path[NG_PATHSIZ], int opt_level, int opt_name, void * restrict optval, socklen_t * restrict optlen );

int get_ksockopts_all ( char path[NG_PATHSIZ] ) {
    char name[NG_NODESIZ];
    socklen_t len;
    struct sock_opts *ptr;
// Make socket node
    if ( NgMkSockNode( name, &csock, &dsock ) < 0 ) {
        printf("Error creating socket node %s", strerror(errno));
        return -1;
    }
// Getting all of it in cycle    
    for ( ptr = sock_opts; ptr->opt_str != NULL; ptr++ ) {
        printf("%s: ", ptr->opt_str);
        if ( ptr->opt_val_str == NULL )
            printf("(undefined)\n");
        else {
            /*
            switch( ptr->opt_level ) {
                case SOL_SOCKET:
                case IPPROTO_IP:
                case IPPROTO_TCP:
                    fd = socket(AF_INET, SOCK_STREAM, 0);
                    break;
                default:
                    printf("Can`t create fd for level %d\n", ptr->opt_level);
                    return 1;
            }
            */
            len = sizeof(val);
            if ( get_ksock_opt(path, ptr->opt_level, ptr->opt_name, &val, &len) == -1 ) {
                printf("%s:%d getsockopt error: %s\n", __FILE__, __LINE__, strerror(errno));
                return -1;
            } else {
                printf("default = %s\n", (*ptr->opt_val_str)(&val, len));
            }
        }
    }
    return 1;
}

int get_ksock_opt( char path[NG_PATHSIZ], int opt_level, int opt_name, void * restrict optval, socklen_t * restrict optlen ) {
    size_t total_len = sizeof(struct ng_ksocket_sockopt) + sizeof(*optlen);
    struct ng_ksocket_sockopt *sockopt = malloc(total_len);

    int one = 1;
    memset(sockopt, 0, total_len);
    sockopt->level = opt_level;
    sockopt->name = opt_name;

    struct ng_mesg *resp;
    //NgSetDebug(3);
    
    if ( NgSendMsg( csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, sockopt, sizeof(*sockopt)) < 0 ) {
        printf("%s:%d Error send msg : %s\n", __FILE__, __LINE__, strerror(errno));
        return -1;
    }
    if ( NgAllocRecvMsg( csock, &resp, 0 ) < 0 ) {
        printf("%s:%d Error recv msg : %s\n", __FILE__, __LINE__, strerror(errno));
        return -1;
    }
    struct ng_ksocket_sockopt *resp_clean = (struct ng_ksocket_sockopt *)resp->data;
    *optlen = resp->header.arglen - sizeof(struct ng_ksocket_sockopt);
    memcpy(optval, (int *)resp_clean->value, *optlen);
    free(resp);
    return 1;
}


int get_sockopt ( void ) {
    int fd;
    socklen_t len;
    struct sock_opts *ptr;

    for ( ptr = sock_opts; ptr->opt_str != NULL; ptr++ ) {
        printf("%s: ", ptr->opt_str);
        if ( ptr->opt_val_str == NULL )
            printf("(undefined)\n");
        else {
            switch( ptr->opt_level ) {
                case SOL_SOCKET:
                case IPPROTO_IP:
                case IPPROTO_TCP:
                    fd = socket(AF_INET, SOCK_STREAM, 0);
                    break;
                default:
                    printf("Can`t create fd for level %d\n", ptr->opt_level);
                    return 1;
            }
            
            len = sizeof(val);
            if ( getsockopt(fd, ptr->opt_level, ptr->opt_name, &val, &len) == -1 ) {
                printf("getsockopt error\n");
                return -1;
            } else {
                printf("default = %s\n", (*ptr->opt_val_str)(&val, len));
            }
        }
    }
    return 1;
}

static char *
sock_str_flag(union val *ptr, int len) {
    if ( len != sizeof(int) )
        snprintf(stress, sizeof(stress), "size (%d) not sizeof(int)", len);
    else
        snprintf(stress, sizeof(stress), "%s", (ptr->i_val == 0) ? "off" : "on");
   return(stress); 
}

static char *
sock_str_int(union val *ptr, int len) {
    if ( len != sizeof(int) )
        snprintf(stress, sizeof(stress), "size (%d) not sizeof(int)", len);
    else
        snprintf(stress, sizeof(stress), "%d", (ptr->i_val));
    return(stress); 

}

static char *
sock_str_linger(union val *ptr, int len) {
    if ( len != sizeof(struct linger) ) 
        snprintf(stress, sizeof(stress), "size (%d) not sizeof(struct linger_val)", len);
    else
        snprintf(stress, sizeof(stress), "l_onoff = %d, l_linger = %d", (ptr->linger_val.l_onoff), (ptr->linger_val.l_linger));
    return(stress);
}

static char *
sock_str_timeval(union val *ptr, int len) {
    if ( len != sizeof(struct timeval) )
        snprintf(stress, sizeof(stress), "size (%d) not sizeof(struct timeval)", len);
    else
        snprintf(stress, sizeof(stress), "%ld sec, %ld usec", (ptr->timeval_val.tv_sec), (ptr->timeval_val.tv_usec));
    return(stress);
}
