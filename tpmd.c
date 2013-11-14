/*
 * tpmd.c
 * Source file for tpmd
 * tpmd (TPM daemon) is a TCP server used to recv the
 * challenge from the arpsecd (ARP security daemon),
 * pass the requset to the local TPM (tcsd) and send
 * the response back to arpsecd. AT protocol is used
 * between the communication between arpsecd and tpmd.
 * For detailes, please read the damn code!
 * Reference: Trousers (tcsd)
 * Nov 12, 2013
 * Added timing for AT msg processing
 * Sep 16, 2013 (my brithday, man)
 * root@davejingtian.org
 * http://davejingtian.org
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include "tpmd.h"
#include "tpmw.h"
#include "AT.h"

extern char *optarg;
static int sd;
static int use_fake_tpm_info;
static int debug_enabled;

static void tpmd_signal_term(int signal)
{
	/* Close the socket */
	close(sd);
	/* Close the TPM */
	tpmw_close_tpm();
}

static int signals_init(void)
{
	int rc;
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	if ((rc = sigaddset(&sigmask, SIGTERM))) {
		printf("tpmd - Error: sigaddset [%s]\n", strerror(errno));
		return -1;
	}

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = tpmd_signal_term;
	if ((rc = sigaction(SIGTERM, &sa, NULL))) {
		printf("tpmd - Error: signal SIGTERM not registered [%s]\n", strerror(errno));
		return -1;
	}

	return 0;
}


static void usage(void)
{
	fprintf(stderr, "\tusage: tpmd [-f] [-c <config file> [-h]\n\n");
	fprintf(stderr, "\t-f|--fake\tuse the fake TPM information (for testing)\n");
	fprintf(stderr, "\t-d|--debug\tenable debug mode\n");
	fprintf(stderr, "\t-c|--config\tpath to configuration file (TBD)\n");
	fprintf(stderr, "\t-h|--help\tdisplay this help message\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct sockaddr_in serv_addr, client_addr;
	int result;
	int newsd, c, option_index = 0;
	unsigned client_len;
	char *hostname = NULL;
	void *recv_buff;
	int recv_size;
	int send_size;
	at_req msg_req;
	at_rep msg_rep;
	struct hostent *client_hostent = NULL;
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"fake", 0, NULL, 'f'},
		{"debug", 0, NULL, 'd'},
		{"config", 1, NULL, 'c'},
		{0, 0, 0, 0}
	};

//daveti: add time measurement for this function call
struct timeval tpstart,tpend;
float timeuse = 0;

	while ((c = getopt_long(argc, argv, "fhdc:", long_options, &option_index)) != -1) {
		switch (c) {
			case 'f':
				printf("tpmd - Info: will use fake TPM info\n");
				use_fake_tpm_info = 1;
				break;
			case 'd':
				printf("tpmd - Info: debug mode enabled\n");
				debug_enabled = 1;
				break;
			case 'c':
				printf("tpmd - Warning: may support in future\n");
				break;
			case 'h':
				/* fall through */
			default:
				usage();
				return -1;
		}
	}

	/* Set the signal handlers */
	if (signals_init() != 0) {
		printf("tpmd - Error: failed to set up the signal handlers\n");
		return -1;
	}

	/* Create the socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		printf("tpmd - Error: Failed socket [%s]\n", strerror(errno));
		return -1;
	}

	/* Set the server address and port */
	memset(&serv_addr, 0, sizeof (serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(TPMD_PORT);

	/* Reuse the addr for TCP socket and bind */
	c = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c));
	if (bind(sd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) {
		printf("tpmd - Error: Failed bind [%s]\n", strerror(errno));
		return -1;
	}

	/* Listen now */
	if (listen(sd, TPMD_MAX_SOCKETS_QUEUED) < 0) {
		printf("tpmd - Error: Failed listen [%s]\n", strerror(errno));
		return -1;
	}
	client_len = (unsigned)sizeof(client_addr);

	/* Prepare for the recv buffer */
	recv_buff = calloc(1, TPMD_RECV_BUFF_LEN);

	/* Init the AT stack */
	at_init_queue(AT_MSG_REQ);

	/* Init the TPM worker - do the dirty job:) */
	result = tpmw_init_tpm(TPMW_MODE_TPMD);
	if (result != 0)
	{
		printf("tpmd - Error: tpmw_init_tpm failed\n");
		return -1;
	}
	
	printf("tpmd - Info: tpmd up and running.\n");
	do {
		/* Accept the connection request */
		newsd = accept(sd, (struct sockaddr *) &client_addr, &client_len);
		if (newsd < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				printf("tpmd - Error: Failed accept [%s]\n", strerror(errno));
				continue;
			}
		}
		printf("tpmd - Info: accepted socket %i\n", newsd);

		/* Try to parse the hostname of the client */
		if ((client_hostent = gethostbyaddr((char *) &client_addr.sin_addr,
						    sizeof(client_addr.sin_addr),
						    AF_INET)) == NULL) {
			char buf[16];
                        uint32_t addr = htonl(client_addr.sin_addr.s_addr);

                        snprintf(buf, 16, "%d.%d.%d.%d", (addr & 0xff000000) >> 24,
                                 (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8,
                                 addr & 0x000000ff);

			printf("tpmd - Warning: Host name for connecting IP [%s] could not be resolved\n", buf);
			hostname = strdup(buf);
		} else {
			hostname = strdup(client_hostent->h_name);
		}
		printf("tpmd - Info: got msgs from hostname [%s]\n", hostname);

		/* Recv the msg from the client */
		recv_size = recv(newsd, recv_buff, TPMD_RECV_BUFF_LEN, 0);
		if (recv_size == -1)
		{
			printf("tpmd - Error: recv failed [%s]\n", strerror(errno));
		}
		else if (recv_size == 0)
		{
			printf("tpmd - Warning: client socket is closed\n");
		}
		else if (recv_size % AT_REQ_LEN != 0)
		{
			printf("tpmd - Error: invalid AT msg size (may be garbage) - drop it\n");
		}
		else if (recv_size / AT_REQ_LEN != 1)
		{
			printf("tpmd - Info: got more than 1 AT msg - push the extras into AT queue\n");
			at_add_msg_queue((void *)(recv_buff+AT_REQ_LEN), (recv_size-AT_REQ_LEN), AT_MSG_REQ);
		}

		memcpy(&msg_req, recv_buff, AT_REQ_LEN);

		/* Handle the first msg and then go thru the queue */
		do
		{
			/* Debug */
			if (debug_enabled == 1)
				at_display_msg_req(&msg_req);

			/* Validate the msg */
			if (at_is_msg_req(&msg_req) != 1)
			{
				/* DDos may be considered here */
				printf("tpmd - Error: invalid AT request - drop it\n");
			}
			else
			{
//daveti: do the time measure
timeuse = 0;
gettimeofday(&tpstart,NULL);
				/* Process the AT request and generate the AT reply */
				if (tpmw_at_req_handler(&msg_rep, &msg_req, use_fake_tpm_info) != 0)
				{
					printf("tpmd - Error: tpmw_req_handler failed\n");
				}
				else
				{
					/* Debug */
					if (debug_enabled == 1)
						at_display_msg_rep(&msg_rep);

					/* Send the reply back */
					send_size = send(newsd, (void *)&msg_rep, AT_REP_LEN, 0);
					if (send_size != AT_REP_LEN)
						printf("tpmd - Error: send failed [%s]\n", strerror(errno));
					else
						printf("tpmd - Info: sent an reply to host [%s]\n", hostname);
				}
//daveti: end timing
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
printf("tpmd - Total time on tpmw_at_req_handler() and send() is [%f] ms\n", timeuse);

			}

		} while ((at_get_msg_num_queue(AT_MSG_REQ) != 0) && (at_pop_head_msg_queue(&msg_req, AT_MSG_REQ) == 0));

		/* Get ready for the next accept */
		free(hostname);
		hostname = NULL;

		/* Close the socket file */
		close(newsd);

	} while (1);

	/* To close correctly, we must receive a SIGTERM */
	return 0;
}
