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

static int csock, dsock; 

int main ( int argc, char *argv[] ) {
    char *socketToGet = "[0008ff7f]:";
    char sockName[NG_PATHSIZ];

    memset( sockName, 0, sizeof(sockName));
    sprintf(sockName, "%s%d", "getsockopt", getpid());
    // "[0008ecf4]:"
    if ( NgMkSockNode("getsockopt-node", &csock, &dsock) < 0 ) {
        printf("Error has occured while creating netgraph socket: %s\n", strerror(errno));
        return 1;
    }
 
    //SetKsocketTos(socketToGet);
    GetKsocketError(socketToGet);
    GetNoDelay(socketToGet);
    SetNoDelay(socketToGet);
    GetNoDelay(socketToGet);
    return 1;
}
/* Get Error from ksocket node if any */
int GetKsocketError(char path[NG_PATHSIZ]) {
    struct ng_ksocket_sockopt *sockopt_resp = malloc(sizeof(struct ng_ksocket_sockopt) + sizeof(int)); 
    struct ng_mesg *resp;
    memset(sockopt_resp, 0, sizeof(struct ng_ksocket_sockopt) + sizeof(int));

    sockopt_resp->level = SOL_SOCKET;
    sockopt_resp->name = SO_ERROR;

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
    NgSetDebug(3);
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
    printf("tos = %d\n", *sockopt_resp->value);    
    if ( NgAllocRecvMsg(csock, &resp, 0 ) < 0 ) {
        printf("Error while trying to get message from getsockopt\n");
        return 1;
    }
   
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


