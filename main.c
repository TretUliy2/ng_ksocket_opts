#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netgraph.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_ksocket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>



int SetNoDelay(char path[NG_PATHSIZ]);
int GetNoDelay(char path[NG_PATHSIZ]);
int SetReusePort(char path[NG_PATHSIZ]);
int GetKsocketError(char path[NG_PATHSIZ]);
int SetKsocketTos (char path[NG_PATHSIZ]);
int GetKsocketTos(char path[NG_PATHSIZ]); 
int SetKsocketKeepAlive (char path[NG_PATHSIZ]);
int GetKsocketKeepAlive (char path[NG_PATHSIZ]); 
int GetKsocketTcpInfo (char path[NG_PATHSIZ]);
int GetKsocketReuseAddr (char path[NG_PATHSIZ]);
int GetKsocketReusePort (char path[NG_PATHSIZ]);
int GetKsocketSendBuf (char path[NG_PATHSIZ]);
int SetKsocketSendBuf (char path[NG_PATHSIZ], int value);
void tcp_info_print (struct tcp_info *);

int printBytes (struct ng_ksocket_sockopt *sockopt, size_t len);

static int csock, dsock; 

int main ( int argc, char *argv[] ) {
    char *socketToGet;
    char sockName[NG_PATHSIZ];
    if ( argc < 2 ) {
        socketToGet = "[98]:";
    } else {
        socketToGet = argv[1];
    }

    memset( sockName, 0, sizeof(sockName));
    sprintf(sockName, "%s%d", "getsockopt", getpid());
    // "[0008ecf4]:"
    if ( NgMkSockNode("getsockopt-node", &csock, &dsock) < 0 ) {
        printf("Error has occured while creating netgraph socket: %s\n", strerror(errno));
        return 1;
    }
 
    GetKsocketTos(socketToGet);
    //GetKsocketError(socketToGet);
    /*
    GetKsocketKeepAlive(socketToGet);
    SetKsocketKeepAlive(socketToGet);
    GetKsocketKeepAlive(socketToGet);
    */
    //GetKsocketTcpInfo(socketToGet);
    return 1;
}
/* Get Error from ksocket node if any */
int GetKsocketError(char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_mesg *resp;
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));

    sockopt_resp->level = SOL_SOCKET;
    sockopt_resp->name = SO_ERROR;
    NgSetDebug(3);
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        fprintf(stderr, "Error while trying to get message from getsockopt: %s\n", strerror(errno));
        return 1;
    }

    int sockError = *((struct ng_ksocket_sockopt *)resp->data)->value; 
    if (sockError != 0) { 
        printf("Error = %d string = %s\n", sockError, strerror(sockError));
    }
    free(sockopt_resp);
    free(resp);
    return 1;
}
/* Set TOS field value of ksocket */
int SetKsocketTos (char path[NG_PATHSIZ]) {
	int tos;
	union {
		u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
		struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt * const sockopt = &sockopt_buf.sockopt;
	struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int));
	struct ng_mesg *m;

	// set dscp value 32 for socket
	sockopt->level = IPPROTO_IP;
	sockopt->name = IP_TOS;
	tos = IPTOS_DSCP_CS4;
	memcpy(sockopt->value, &tos, sizeof(tos));
	if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_SETOPT,
			sockopt, sizeof(sockopt_buf) ) == -1) {
		fprintf(stderr, "%s(): Sockopt set failed : %s\n", __FUNCTION__,
				strerror(errno));
		return 0;
	} else  {
		memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));
		sockopt_resp->level = IPPROTO_IP;
		sockopt_resp->name = IP_TOS;
		// Trying to get option we just set
		if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT,
        		sockopt_resp, sizeof(*sockopt_resp)) == -1) {
        	fprintf(stderr, "%s() can`t get sockopt from address :%s because : %s\n", __FUNCTION__,
        			path, strerror(errno));
        	return 0;
        }

		if (NgAllocRecvMsg(csock, &m, NULL) < 0) {
			fprintf(stderr,  "%s() Error receiving response\n", __FUNCTION__);
		} else {
			fprintf(stderr, "%s() message received dscp = %d trying to set = %d another value = %d\n",
					__FUNCTION__, *((struct ng_ksocket_sockopt *)m->data)->value, IPTOS_DSCP_CS4, *sockopt_resp->value );
			free(m);
		}

		//fprintf(stderr, "%s(): sockopt_resp.value = 0x%08x must be = 0x%08x",
		//		__FUNCTION__, sockopt_resp->value, IPTOS_DSCP_CS4);

        //sockopt_resp = (struct ng_ksocket_sockopt *)m->data;
        //Log(LOG_NOTICE, "%s(): m->header.token = %d sockopt->value = %s"
        //		, __FUNCTION__,
		//		m->header.token, sockopt_resp->value);

		//fprintf(stderr, "%s() tos = %d set for socket success", __FUNCTION__, tos);
        return 1;
    }
	return 1;
}


/* Get TOS field value from ksocket node */ 
int GetKsocketTos(char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_mesg *resp;
    
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));
    sockopt_resp->level = IPPROTO_IP;
    sockopt_resp->name = IP_TOS;
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        printf("Error while trying to get message from getsockopt\n");
        return 1;
    }
    struct ng_ksocket_sockopt *resp_sockopt = (struct ng_ksocket_sockopt *)resp->data;
    int tos = *((int *)resp_sockopt->value);
    printf("%s:%d tos in resp = %d\n", __FILE__, __LINE__, tos); 
    free(sockopt_resp);
    free(resp);
    
    return 1;
}
/* Set NO DELAY */
int SetNoDelay ( char path[NG_PATHSIZ] )  {
	union {
		u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
		struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt * const sockopt = &sockopt_buf.sockopt;
	int one = 1;

	// setsockopt resolve TIME_WAIT problem
	// setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(int)) < 0)
	memset(&sockopt_buf, 0, sizeof(sockopt_buf));

	sockopt->level = IPPROTO_TCP;
	sockopt->name = TCP_NODELAY;
	memcpy(sockopt->value, &one, sizeof(int));
	if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_SETOPT,
			sockopt, sizeof(sockopt_buf)) == -1) {
		fprintf(stderr, "%s(): Sockopt set failed : %s\n", __FUNCTION__,
				strerror(errno));
		return -1;
	}
	return 1;
}
/* GET NO DELAY*/
int GetNoDelay ( char path[NG_PATHSIZ] )  {
    struct ng_ksocket_sockopt *sockopt = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int));
    struct ng_mesg *resp;

	// setsockopt resolve TIME_WAIT problem
	// setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(int)) < 0)

	sockopt->level = IPPROTO_TCP;
	sockopt->name = TCP_NODELAY;

	if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT,
			sockopt, sizeof(struct ng_ksocket_sockopt)) == -1) {
		fprintf(stderr, "%s(): Sockopt set failed : %s\n", __FUNCTION__,
				strerror(errno));
		return -1;
	}

    if (NgAllocRecvMsg(csock, &resp, 0) < 0 ) {
        fprintf(stderr, "Error receiving answer to getsockopt: %s\n", strerror(errno));
        return 1;
    }
    printf("TCP_NODELAY = %d\n", *((struct ng_ksocket_sockopt *)resp->data)->value );

    free(resp);
	return 1;
}


int SetReusePort (char path[NG_PATHSIZ]) {
	union {
		u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
		struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt * const sockopt = &sockopt_buf.sockopt;
	int one = 1;

	// setsockopt resolve TIME_WAIT problem
	// setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(int)) < 0)
	memset(&sockopt_buf, 0, sizeof(sockopt_buf));

	sockopt->level = SOL_SOCKET;
	sockopt->name = SO_REUSEADDR;
	memcpy(sockopt->value, &one, sizeof(int));
	if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_SETOPT,
			sockopt, sizeof(sockopt_buf)) == -1) {
		fprintf(stderr, "%s(): Sockopt set failed : %s\n", __FUNCTION__,
				strerror(errno));
		return -1;
	}
	sockopt->name = SO_REUSEPORT;
	if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_SETOPT,
				sockopt, sizeof(sockopt_buf)) == -1) {
			fprintf(stderr, "%s(): Sockopt set failed : %s\n", __FUNCTION__,
					strerror(errno));
			return -1;
	}
	return 1;
}


int SetKsocketKeepAlive (char path[NG_PATHSIZ]) {
	union {
		u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
		struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt * const sockopt = &sockopt_buf.sockopt;
	int one = 1;

	// setsockopt resolve TIME_WAIT problem
	// setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(int)) < 0)
	memset(&sockopt_buf, 0, sizeof(sockopt_buf));

	sockopt->level = SOL_SOCKET;
	sockopt->name = SO_KEEPALIVE;
	memcpy(sockopt->value, &one, sizeof(int));
	if (NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_SETOPT,
			sockopt, sizeof(sockopt_buf)) == -1) {
		fprintf(stderr, "%s(): Sockopt set failed : %s\n", __FUNCTION__,
				strerror(errno));
		return -1;
	}
	return 1;
}

int GetKsocketKeepAlive (char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 

    struct ng_mesg *resp;
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));

    sockopt_resp->level = SOL_SOCKET;
    sockopt_resp->name = SO_KEEPALIVE;
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        fprintf(stderr, "Error while trying to get message from getsockopt: %s\n", strerror(errno));
        return 1;
    }
    struct ng_ksocket_sockopt *sk;
    sk = (struct ng_ksocket_sockopt *)resp->data;
    printBytes(sk, resp->header.arglen);
    int option = *((int *)sk->value); 
    printf("KEEPALIVE = %d\n", option);
     
    free(sockopt_resp);
    free(resp);
    return 1;
}

int GetKsocketSendBuf (char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_ksocket_sockopt *sk;
    struct ng_mesg *resp;
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));

    sockopt_resp->level = SOL_SOCKET;
    sockopt_resp->name = SO_SNDBUF;
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        fprintf(stderr, "Error while trying to get message from getsockopt: %s\n", strerror(errno));
        return 1;
    }
    sk = (struct ng_ksocket_sockopt *)resp->data;
    int option = *((int *)sk->value); 
    printBytes(sk, resp->header.arglen);
    printf("SO_SNDBUF = %d\n", option);
     
    free(sockopt_resp);
    free(resp);
    return 1;
}

int SetKsocketSendBuf (char path[NG_PATHSIZ], int value) {
    union {
		u_char buf[sizeof(struct ng_ksocket_sockopt) + sizeof(int)];
		struct ng_ksocket_sockopt sockopt;
	} sockopt_buf;
	struct ng_ksocket_sockopt * const sockopt = &sockopt_buf.sockopt;

    struct ng_ksocket_sockopt *sk;
    struct ng_mesg *resp;
    size_t sockopt_len = sizeof(struct ng_ksocket_sockopt) + sizeof(int);

    memset(sockopt, 0, sizeof(sockopt_buf));

    sockopt->level = SOL_SOCKET;
    sockopt->name = SO_SNDBUF;
    memcpy(sockopt->value, &value, sizeof(value));
    NgSetDebug(3);
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_SETOPT, 
                            sockopt, sizeof(sockopt_buf)) == -1 ) {
        printf("Error while trying to set sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    NgSetDebug(0);
    return 1;
}

int GetKsocketReusePort (char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_mesg *resp;
    memset(sockopt_resp, 0, (sizeof(struct ng_ksocket_sockopt) + sizeof(int)));
    sockopt_resp->level = SOL_SOCKET;
    sockopt_resp->name = SO_REUSEPORT;
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        fprintf(stderr, "Error while trying to get message from getsockopt: %s\n", strerror(errno));
        return 1;
    }
    
    int *option = (int *)(((struct ng_ksocket_sockopt *)resp->data)->value); 
    printf("REUSEPORT = %d\n", htons(*option));
    free(sockopt_resp);
    free(resp);
    return 1;

}

int GetKsocketReuseAddr (char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_mesg *resp;
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));

    sockopt_resp->level = SOL_SOCKET;
    sockopt_resp->name = SO_REUSEPORT;
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        fprintf(stderr, "Error while trying to get message from getsockopt: %s\n", strerror(errno));
        return 1;
    }
    int *option = (int *)((struct ng_ksocket_sockopt *)&resp->data)->value; 
    printf("REUSEADDR = %d\n", htons(*option));
     
    free(sockopt_resp);
    free(resp);
    return 1;

}


int GetKsocketTcpInfo (char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_mesg *resp;
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));

    sockopt_resp->level = IPPROTO_TCP;
    sockopt_resp->name = TCP_INFO;
    //NgSetDebug(3);
    if ( NgSendMsg(csock, path, NGM_KSOCKET_COOKIE, NGM_KSOCKET_GETOPT, 
                            sockopt_resp, sizeof(*sockopt_resp)) == -1 ) {
        printf("Error while trying to get sockopt from %s - %s\n", 
                        path, strerror(errno));
        return 1;
    }
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        fprintf(stderr, "Error while trying to get message from getsockopt: %s\n", strerror(errno));
        return 1;
    }
    printf("resp.arglen = %d sizeof(struct tcp_info) = %d\n", resp->header.arglen, sizeof(struct tcp_info)+sizeof(struct ng_ksocket_sockopt)); 
    struct tcp_info *info;
    info = (struct tcp_info *)((struct ng_ksocket_sockopt *)resp->data)->value;
    tcp_info_print(info);
    free(sockopt_resp);
    free(resp);
    return 1;
}

void tcp_info_print (struct tcp_info *info) {
    printf("strct tcp_info {\n");
    printf("\ttcpi_state = %d\n", info->tcpi_state);
    printf("\t__tcpi_ca_state = %d\n", info->__tcpi_ca_state);
    printf("\t__tcpi_retransmits = %d\n", info->__tcpi_retransmits);
    printf("\t__tcpi_probes = %d\n", info->__tcpi_probes);
    printf("\t__tcpi_backoff = %d\n", info->__tcpi_backoff);
    printf("\ttcpi_options = %d\n", info->tcpi_options);
    printf("\ttcpi_rto = %d\n", info->tcpi_rto);
    printf("\t__tcpi_ato = %d\n", info->__tcpi_ato);
    printf("\ttcpi_snd_mss = %d\n", info->tcpi_snd_mss);
    printf("\ttcpi_rcv_mss = %d\n", info->tcpi_rcv_mss);
    printf("};\n");
}

int printBytes (struct ng_ksocket_sockopt *sockopt, size_t len) {
    int i;
    size_t value_len = len - sizeof(struct ng_ksocket_sockopt);
    //fprintf("Received otion of size %lu\n", value_len);
    for (i = 0; i < value_len; i++ ) {
        fprintf(stderr, "sockopt->value[%d] = %02x\n", i, sockopt->value[i]);
    }
}
