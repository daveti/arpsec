////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsTMeasure.c
//  Description   : The AsTMeasure module implements a shim for the system
//                  trust validation for the arpsec deamon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 09:33:11 EDT 2013
//  Dev	    : daveti
//  Modified: Fri Sep 20 10:27:37 PDT 2013

// Includes

// Project Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "AsDefs.h"
#include "AsLog.h"
#include "AsKrnRelay.h"
#include "AsNetlink.h"
#include "AsTMeasure.h"
#include "AsTpmDB.h"
#include "AT.h"
#include "tpmw.h"

// Make it zero once debugging is done
static int	ast_debug_enabled = 1;
static int	ast_allow_binding;

////////////////////////////////////////////////////////////////////////////////
//
// Function     : astAllowBinding
// Description  : Allow binding if no DB entry found during attestation
//
// Inputs       : void
// Outputs      : void
// Dev          : daveti
//

void astAllowBinding(void)
{
	ast_allow_binding = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : astInitAttest
// Description  : Init the Attest subsystem
//
// Inputs       : mode - running mode (sim/relay)
// Outputs      : 0 if successful, -1 if not
// Dev          : daveti
//

int astInitAttest(int mode)
{
        // Set the mode appropriately
        if ((mode != ASKRN_SIMULATION) && (mode != ASKRN_RELAY))
        {
                asLogMessage("Error on arpsecd mode [%d], aborting", mode);
                return -1;
        }

        // Return success for simulation mode
        if (mode == ASKRN_SIMULATION)
                return 0;

	// Init the AT stack
        at_init_queue(AT_MSG_REP);

        /* Init the TPM worker - do the dirty job:) */
        if (tpmw_init_tpm(TPMW_MODE_ARPSECD) != 0)
	{
		asLogMessage("Error on tpmw_init_tpm");
		return -1;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : astFindDBEntry
// Description  : Find the DB entry based on the msg recv'd
//
// Inputs       : msg - askRelayMessage pointer
// Outputs      : tpmdb_entry pointer (NULL if none)
// Dev          : daveti
//

tpmdb_entry *astFindDBEntry(askRelayMessage *msg)
{
	tpmdb_entry *entry;
	char mac[ARPSEC_NETLINK_STR_MAC_LEN] = {0};
	char ip[ARPSEC_NETLINK_STR_IPV4_LEN] = {0};;

	// Hunt for the entry using MAC at first
	asnLogicMacToStringMac(msg->sndr, mac);
	entry = astdbFindEntryBasedOnMac(mac);

	// Hunt for the entry using IPv4 then
	if (entry == NULL)
	{
		asLogMessage("Warning: Unable to find DB entry using MAC [%s] - try IPv4");
		asnLogicIpToStringIp(msg->sndr_net, ip);
		entry = astdbFindEntryBasedOnIp(ip);
		if (entry == NULL)
			asLogMessage("Warning: Unable to find DB entry using IP [%s]", ip);
		else
			asLogMessage("Info: found DB entry using IP [%s]", ip);
	}
	else
		asLogMessage("Info: found DB entry using MAC [%s]", mac);

	return entry;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : astAttestSystem
// Description  : Attest that the system is in a good state
//
// Inputs       : s - system to attest
// Outputs      : 0 if successful, -1 if not
// Dev		: daveti
//
//int astAttestSystem( AsSystem s ) {
//    return( 1 );
//}

int astAttestSystem(askRelayMessage *msg)
{
        int sock_fd;
        int ret;
        struct addrinfo hints;
        struct addrinfo *res;
	struct timeval tv;
        unsigned char sock_buff[AST_SOCK_BUFF_SIZE];
	tpmdb_entry *entry;
	at_req	req;
	at_rep	rep;

//daveti: timing for attestation
struct timeval tpstart,tpend;
float timeuse = 0;
gettimeofday(&tpstart,NULL);

	// Find the corresponding DB entry
	entry = astFindDBEntry(msg);
	if (entry == NULL)
	{
		if (ast_allow_binding == 0)
		{
			asLogMessage("Error on astFindDBEntry [unable to find the DB entry]");
			return -1;
		}
		else
		{
			asLogMessage("Warning: unable to find the DB entry but allow the binding");
			return 0;
		}
	}

	// Load the PCR mask and PCR values into TPMW
	tpmw_load_db_entry(entry->pcrMask,
			entry->pcrGoodValue,
			entry->pcrLen,
			entry->aikPubKey,
			entry->aikPubKeyLen);

	// Generate the challenge (AT request)
	ret = tpmw_generate_at_req(&req);
	if (ret != 0)
	{
		asLogMessage("Error on tpmw_generate_at_req");
		return -1;
	}

        // Init the socket address
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        // Get the socket address       
        ret = getaddrinfo(entry->ipv4,
                        AST_REMOTE_TPMD_PORT_STRING,
                        &hints, &res);
        if (ret != 0)
        {
                asLogMessage("Errror on getaddinfo [%s]", gai_strerror(ret));
                return -1;
        }

        // Open the socket
        sock_fd = socket(res->ai_family,
                        res->ai_socktype,
                        res->ai_protocol);
        if (sock_fd == -1)
        {
                asLogMessage("Error on socket [%s]", strerror(errno));
                return -1;
        }

        // Connect the socket
        memset(sock_buff, 0, sizeof(sock_buff));
        inet_ntop(res->ai_family,
                &(((struct sockaddr_in*)res->ai_addr)->sin_addr),
                sock_buff, sizeof(sock_buff));
        asLogMessage("arpsecd astAttest TCP client connecting to [%s]", sock_buff);

        ret = connect(sock_fd, res->ai_addr, res->ai_addrlen);
        if (ret == -1)
        {
                asLogMessage("Error on connect [%s]", strerror(errno));
		goto close;
        }

	// Dump the AT request
	if (ast_debug_enabled == 1)
		at_display_msg_req(&req);

	// Send the challenge to the remote machine
	memcpy(sock_buff, &req, AT_REQ_LEN);
        ret = send(sock_fd, sock_buff, AT_REQ_LEN, 0);
        if (ret == -1)
        {
                asLogMessage("Error on send [%s]", strerror(errno));
		goto close;
        }
        asLogMessage("arpsecd astAttest sent the challenge and wait for the response");

	// Set the timeout for the recv
	tv.tv_sec = AST_SOCK_RECV_TIMEOUT;  /* 2 Secs Timeout */
	tv.tv_usec = 0;  // Not init'ing this can cause strange errors
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	if (ret == -1)
	{
		asLogMessage("Error on setsockopt [%s]", strerror(errno));
		goto close;
	}

	// Recv the attestation (AT reply) from the remote machine
        memset(sock_buff, 0, sizeof(sock_buff));
        ret = recv(sock_fd, sock_buff, sizeof(sock_buff), 0);
        if (ret == -1)
        {
                asLogMessage("Error on recv [%s]", strerror(errno));
		goto close;
        }
	else if (ret == 0)
	{
		asLogMessage("Warning: tpmd socket closed or timeout");
		ret = -1;
		goto close;
	}
	else if (ret % AT_REP_LEN != 0)
	{
		asLogMessage("Error: invalid msg size [%d] for AT reply [%d]",
				ret, AT_REP_LEN);
		ret = -1;
		goto close;
	}
	else if (ret / AT_REP_LEN != 1)
	{
		asLogMessage("Info: got [%d] AT replies - will push the extras into AT queue",
				ret/AT_REP_LEN);
		at_add_msg_queue((void *)(sock_buff+AT_REP_LEN), (ret-AT_REP_LEN), AT_MSG_REP);
	}

	memcpy(&rep, sock_buff, AT_REP_LEN);
	ret = -1;

//daveti: timing for AT reply processing
struct timeval tpstart1,tpend1;
float timeuse1 = 0;

	/* Handle the first msg and then go thru the queue */
	do
	{
		/* Debug */
		if (ast_debug_enabled == 1)
			at_display_msg_rep(&rep);

		/* Validate the msg */
		if (at_is_msg_rep(&rep) != 1)
		{
			/* DDos may be considered here */
			asLogMessage("Error: invalid AT reply - drop it");
		}
		else
		{
			/* Process the AT reply and do the verification */

//daveti: timing for AT reply
timeuse1 = 0;
gettimeofday(&tpstart1,NULL);

			ret = tpmw_at_rep_handler(&rep);

//daveti: timing end for AT reply
gettimeofday(&tpend1,NULL);
timeuse1=1000000*(tpend1.tv_sec-tpstart1.tv_sec)+tpend1.tv_usec-tpstart1.tv_usec;
timeuse1/=1000000;
asLogMessage("Total time on tpmw_at_rep_handler_in_attestation() is [%f] ms", timeuse1);

			if (ret != 0)
			{
				asLogMessage("Error: attestation failed for remote [%s]",
						msg->source);
			}
			else
			{
				asLogMessage("Info: attestation succeeded for remote [%s]",
						msg->source);
				/* Ignore the left msgs in the queue */
				at_clear_all_msg_queue(AT_MSG_REP);
				ret = 0;
			}
		}

	} while ((at_get_msg_num_queue(AT_MSG_REP) != 0) && (at_pop_head_msg_queue(&rep, AT_MSG_REP) == 0));

close:
	freeaddrinfo(res);
	close(sock_fd);

//daveti timing end
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
asLogMessage("Total time on Attestation_Run() is [%f] ms", timeuse);

	return ret;
}

