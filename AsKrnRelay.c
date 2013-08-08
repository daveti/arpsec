////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsKrnRelay.c
//  Description   : The AsKrnRelay module implements the interface inbetwee
//                  the kernel and the daemon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 09:33:11 EDT 2013
//
//  daveti  : Jul 30, 2013
//

// Includes
#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

// Project Includes
#include "AsKrnRelay.h"
#include "AsLog.h"
#include "AsControl.h"

// Defines
#define MAX_SIM_VALS 10
#define AS_SIMMSG_FREQ 25
#define PIPE_NAME "input.pipe"

// Module local data
int     pipefd;

// daveti: relayfd is used instead of pipefd
int	relayfd[ARPSEC_MAX_NUM_OF_CPUS]    = {0};	// Relay file handler array
int	relayidx;					// Relay file handler index
int	ask_initialized	    = 0;		// Intialized flag
int	ask_operating_mode  = ASKRN_UNKNOWN;    // Mode variable
char	askSimSystems[MAX_SIM_VALS][128];	// Simluated systems	
long	askSimIPs[MAX_SIM_VALS];		// Simulated IPs
char	askSimIPStrings[MAX_SIM_VALS][128];	// Simulated IP strings
char	askSimEths[MAX_SIM_VALS][6];		// Simulated media addresses
char	askSimEthStrings[MAX_SIM_VALS][128];	// Simulated media strings

// Strings associated with the different message types
char * askOpCodeStrings[4] = {
     "RFC_826_ARP_REQ", "RFC_826_ARP_RES",
     "RFC_903_ARP_RREQ", "RFC_903_ARP_RRES"
};

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askInitRelay
// Description  : Initialize the relay code (mode is sym vs. kern)
//
// Inputs       : the kind of "mode" to operate in SIM vs. REAL
// Outputs      : 0 if successful, -1 if failure 

int askInitRelay( int mode ) {

    // Set the mode appropriately
    if ( (mode != ASKRN_SIMULATION) && (mode != ASKRN_RELAY) ) {
	asLogMessage( "Bad kernel relay mode [%d], aborting", mode );
	return( -1 );
    }
    ask_operating_mode = mode;

    // If simluating setup some hosts
    if ( mode == ASKRN_SIMULATION ) {
	askSetupSimulation();
    }

    // Otherwise initialize system
    else {
      printf("Opening pipe from kernel space\n");
        //pipefd = askGetRelayHandle();
	// daveti:
	// setup the local info and
	// get the file handlers for relay
	if (askSetupLocalInfo() == -1)
	{
		asLogMessage("Error on askSetupLocalInfo - aborting the askInitRelay");
		return -1;
	}
	ascDumpLocalInfo();
	askGetRelayHandle2();
    } 

    // Setup intialized, return successfully
    ask_initialized = 1;
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askShutdownRelay
// Description  : Close the relay 
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure 
// Dev		: daveti

int askShutdownRelay( void ) {

	// Setup intialized, return successfully
	ask_initialized = 0;

	// daveti: do nothing for simulation mode
	if (ask_operating_mode == ASKRN_RELAY)
	{
		// free the memory for setup local info
		ascReleaseMemForLocalInfo();

		// close the files for relay
		int i;
		for (i = 0; i < ARPSEC_MAX_NUM_OF_CPUS; i++)
		{
			if (relayfd[i] != 0)
				close(relayfd[i]);
			else
				break;
		}

		// umount the debugfs
		if (umount(ARPSEC_DEBUGFS) == -1)
			asLogMessage("Error on umount [%s]", strerror(errno));
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetRelayHandle
// Description  : Get a reference to the relay file handle (used for selecting)
//
// Inputs       : none
// Outputs      : the file handle or -1 if no handle to get (SIM mode) 

int askGetRelayHandle( void ) {

    // if simulating, then return no handle
    if ( ask_operating_mode ==  ASKRN_SIMULATION ) {
	return( -1 );
    }

    else {
      // open the pipe here for input from relay
    }
    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetRelayHandle2
// Description  : Get a reference to the relay file handles (used for selecting)
//
// Inputs       : none
// Outputs      : void
// Dev		: daveti

void askGetRelayHandle2( void ) {

    // if simulating, then return no handle
    if ( ask_operating_mode ==  ASKRN_SIMULATION ) {
        return;
    }

    else {
      // mount the debugfs at first
      if (mount("debugfs", ARPSEC_DEBUGFS, "debugfs", 0, NULL) == -1) {
	asLogMessage("Error on mount debugfs [%s]", strerror(errno));
	printf("mount debugfs failed\n");
	return;
      }

      // open the files here for input from relay
      int num_of_cpu = sysconf(_SC_NPROCESSORS_CONF);
      asLogMessage("arpsecd got [%d] CPUs", num_of_cpu);
      if (num_of_cpu == -1) {
	asLogMessage("Error on sysconf [%s]", strerror(errno));
      }
      else if (num_of_cpu > ARPSEC_MAX_NUM_OF_CPUS) {
	asLogMessage("Error on exceeding the max num of cpus");
      }

      else {
	// open all the relay files
	char filename[ARPSEC_RELAY_FILE_BUFF];
	int i;
	int fd;
	for (i = 0; i < num_of_cpu; i++) {
	    memset(filename, 0, ARPSEC_RELAY_FILE_BUFF);
	    snprintf(filename, ARPSEC_RELAY_FILE_BUFF, "%s%d", ARPSEC_RELAY_FILE, i);
	    fd = open(filename, O_RDONLY);
	    if (fd == -1) {
		asLogMessage("Error on open [%s] for file %s", strerror(errno), filename);
		continue;
	    } else {
		 asLogMessage("Relay opened for file %s", filename);
	    }

	    // Add this fd into relayfd
	    relayfd[relayidx] = fd;
	    relayidx++;
	}
      }
    }
    // Return successfully
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetRelayHandle3
// Description  : Get a reference to the relay file handles (used for selecting)
//
// Inputs       : none
// Outputs      : int *
// Dev          : daveti

int * askGetRelayHandle3( void ) {

    // if simulating, then return no handle
    if ( ask_operating_mode ==  ASKRN_SIMULATION ) {
        return NULL;
    }
    else {
	return relayfd;
    }
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetNextMessage 
// Description  : Get the next message off the relay, or nothing if non available
//
// Inputs       : none
// Outputs      : buffer if got message, NULL otherwise
// Dev		: daveti

askRelayMessage * askGetNextMessage( void ) {

    // Local variables
    askRelayMessage *msg = NULL;
    char read_buffer[ARPSEC_RELAY_BUFFLEN];
    arpsec_arpmsg *arp_msg_ptr;
    int num_of_read;
    int i;

    // If simulating, randomly generate a message (probablistically)
    if ( ask_operating_mode ==  ASKRN_SIMULATION ) {
	    
	if ( as_random(100) < AS_SIMMSG_FREQ ) {
	    msg = askGenerateSimMessage();
	}

    } else {

	// Normal kernel processing here
	// asLogMessage( "TODO: implement kernel interface" );
	// daveti: Read from relayfd to see if there is anything
	for (i = 0; i < ARPSEC_MAX_NUM_OF_CPUS; i++) {
		if (relayfd[i] == 0)
			break;

		num_of_read = read(relayfd[i], read_buffer, ARPSEC_RELAY_BUFFLEN);
		if (num_of_read == -1) {
			// bad read
			asLogMessage("Error on read [%s] for file [%d]", strerror(errno), relayfd[i]);
			continue;
		}
		else if (num_of_read == 0) {
			// nothing to read
			// asLogMessage("Info: nothing to read for file [%d]", relayfd[i]);
			continue;
		}
		else if (num_of_read % ARPSEC_PKG_SIZE) {
			// broken msg
			asLogMessage("Error on broken msg from kernel for file [%d]", relayfd[i]);
			continue;
		}
		else if (num_of_read / ARPSEC_PKG_SIZE != 1) {
			// more than 1 msg got the same time
			// may need enhancement to queue all the msgs...
			// currently only warning with processing
			// this first msg...
			printf("daveti: got more than 1 ARP msg from one CPU\n");
		}

		// read this buffer like arp_msg
		asLogMessage("Info: read on msg from kernel for file [%d]", relayfd[i]);
		arp_msg_ptr = (arpsec_arpmsg *)malloc(ARPSEC_PKG_SIZE);
		memcpy(arp_msg_ptr, read_buffer, ARPSEC_PKG_SIZE);
		
		// convert the arpmsg into askRelayMsg...
		msg = askConvertArpmsg(arp_msg_ptr);
		free(arp_msg_ptr);

		// check if this is a valid ARP/RARP msg...
		if (msg) {
			break;
		} else {
			asLogMessage("Error on askConvertArpmsg - move on");
		}
	}
    }

    // Return successfully
    return( msg );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askSubmitMessage 
// Description  : send a message to the kernel
//
// Inputs       : buf - the buffer to send to kernel
// Outputs      : 0 if successful, -1 if failure 
// Dev		: daveti

int askSubmitMessage( askRelayMessage *buf ) {

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArHrdFromArpmsg
// Description  : get format of hardware address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : int
// Dev          : daveti

int askGetArHrdFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	unsigned char c1 = arp_ptr->ar_hrd[0];
	unsigned char c2 = arp_ptr->ar_hrd[1];
	int format = (c1<<8) + c2;
	return(format);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArProFromArpmsg
// Description  : get format of protocol address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : int
// Dev          : daveti

int askGetArProFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	unsigned char c1 = arp_ptr->ar_pro[0];
	unsigned char c2 = arp_ptr->ar_pro[1];
	int format = (c1<<8) + c2;
	return(format);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArHlnFromArpmsg
// Description  : get length of hardware address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : int
// Dev          : daveti

int askGetArHlnFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	return(arp_ptr->ar_hln);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArPlnFromArpmsg
// Description  : get length of protocol address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : int
// Dev          : daveti

int askGetArPlnFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	return(arp_ptr->ar_pln);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetOpcodeFromArpmsg
// Description  : get ARP opcode from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : int
// Dev          : daveti

int askGetOpcodeFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	unsigned char c1 = arp_ptr->ar_op[0];
	unsigned char c2 = arp_ptr->ar_op[1];
	int opcode = (c1<<8) + c2;
	return(opcode);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArShaFromArpmsg
// Description  : get sender hardware address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : char *
// Dev          : daveti

char * askGetArShaFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	char *mac_ptr = (char *)malloc(ARPSEC_MAC_ADDRESS_LEN);
	// snprintf(mac_ptr, ARPSEC_MAC_ADDRESS_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
	// Use arpsecd format
	snprintf(mac_ptr, ARPSEC_MAC_ADDRESS_LEN, "media%x_%x_%x_%x_%x_%x",
		arp_ptr->ar_sha[0],
		arp_ptr->ar_sha[1],
		arp_ptr->ar_sha[2],
		arp_ptr->ar_sha[3],
		arp_ptr->ar_sha[4],
		arp_ptr->ar_sha[5]);
	return(mac_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArSipFromArpmsg
// Description  : get sender IP address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : char *
// Dev          : daveti

char * askGetArSipFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	char *ip_ptr = (char *)malloc(ARPSEC_IP_ADDRESS_LEN);
	// snprintf(ip_ptr, ARPSEC_IP_ADDRESS_LEN, "%u.%u.%u.%u",
	// Use arpsecd format
	snprintf(ip_ptr, ARPSEC_IP_ADDRESS_LEN, "net%u_%u_%u_%u",
		arp_ptr->ar_sip[0],
		arp_ptr->ar_sip[1],
		arp_ptr->ar_sip[2],
		arp_ptr->ar_sip[3]);
	return(ip_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArSipFromArpmsg2
// Description  : get sender IP address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : char *
// Dev          : daveti

char * askGetArSipFromArpmsg2(arpsec_arpmsg *arp_ptr)
{
        char *ip_ptr = (char *)malloc(ARPSEC_IP_ADDRESS_LEN);
        snprintf(ip_ptr, ARPSEC_IP_ADDRESS_LEN, "%u.%u.%u.%u",
                arp_ptr->ar_sip[0],
                arp_ptr->ar_sip[1],
                arp_ptr->ar_sip[2],
                arp_ptr->ar_sip[3]);
        return(ip_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArThaFromArpmsg
// Description  : get target hardware address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : char *
// Dev          : daveti

char * askGetArThaFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	char *mac_ptr = (char *)malloc(ARPSEC_MAC_ADDRESS_LEN);
	// snprintf(mac_ptr, ARPSEC_MAC_ADDRESS_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
	// Use arpsecd format
	snprintf(mac_ptr, ARPSEC_MAC_ADDRESS_LEN, "media%x_%x_%x_%x_%x_%x",
		arp_ptr->ar_tha[0],
		arp_ptr->ar_tha[1],
		arp_ptr->ar_tha[2],
		arp_ptr->ar_tha[3],
		arp_ptr->ar_tha[4],
		arp_ptr->ar_tha[5]);
	return(mac_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGetArTipFromArpmsg
// Description  : get target IP address from kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : char *
// Dev          : daveti

char * askGetArTipFromArpmsg(arpsec_arpmsg *arp_ptr)
{
	char *ip_ptr = (char *)malloc(ARPSEC_IP_ADDRESS_LEN);
	// snprintf(ip_ptr, ARPSEC_IP_ADDRESS_LEN, "%u.%u.%u.%u",
	// Use arpsecd format
	snprintf(ip_ptr, ARPSEC_IP_ADDRESS_LEN, "net%u_%u_%u_%u",
		arp_ptr->ar_tip[0],
		arp_ptr->ar_tip[1],
		arp_ptr->ar_tip[2],
		arp_ptr->ar_tip[3]);
	return(ip_ptr);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askValidateArpmsg
// Description  : validate the kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : int 0 (success), -1 (faliure)
// Dev          : daveti

int askValidateArpmsg(arpsec_arpmsg *arp_ptr)
{
	int value;

	// Check the format of hardware address
	value = askGetArHrdFromArpmsg(arp_ptr);
	if (value != 1) {
		asLogMessage("Error on format of hardware address [%u]", value);
		return -1;
	}

	// Check the format of protocol address
	value = askGetArProFromArpmsg(arp_ptr);
	if (value != 0x0800) {
		asLogMessage("Error on format of protocol address [%u]", value);
		return -1;
	}

	// Check the length of hardware address
	value = askGetArHlnFromArpmsg(arp_ptr);
	if (value != ARPSEC_ETH_ALEN) {
		asLogMessage("Error on length of hardware address [%u]", value);
		return -1;
	}

	// Check the length of protocol address
	value = askGetArPlnFromArpmsg(arp_ptr);
	if (value != ARPSEC_IPV4_ALEN) {
		asLogMessage("Error on length of protocol address [%u]", value);
		return -1;
	}

	// Check the ARP opcode
	value = askGetOpcodeFromArpmsg(arp_ptr);
	if ((value != ARPSEC_ARPOP_REQUEST) &&
		(value != ARPSEC_ARPOP_REPLY) &&
		(value != ARPSEC_ARPOP_RREQUEST) &&
		(value != ARPSEC_ARPOP_RREPLY))
	{
		asLogMessage("Error on not supported opcode [%u]", value);
		return -1;
	}

	// Leave the MAC/IP validation to upper level
	return 0; 
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askDumpArpmsg
// Description  : dump the whole kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : void
// Dev		: daveti

void askDumpArpmsg(arpsec_arpmsg *arp_ptr) {

	int i;
	unsigned char *ptr = (unsigned char *)arp_ptr;

	asLogMessage("Start dumping the kernel arpmsg");
	asLogMessage("===============================");

	for (i = 0; i < ARPSEC_PKG_SIZE; i++) {
		asLogMessage("arpmsg[%d] = 0x%x(%u)", i, ptr[i], ptr[i]);
	}

	asLogMessage("===============================");
	asLogMessage("End dumping the kernel arpmsg");
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askDumpArpmsg2
// Description  : dump the whole kernel arpmsg
//
// Inputs       : arp_ptr - pointer to the kernel arpmsg
// Outputs      : void
// Dev          : daveti

void askDumpArpmsg2(arpsec_arpmsg *arp_ptr)
{
	char *tmp_ptr;

        asLogMessage("Start dumping(2) the kernel arpmsg");
        asLogMessage("==================================");

	asLogMessage("format_of_hardware_address: %u",
			askGetArHrdFromArpmsg(arp_ptr));
	asLogMessage("format_of_protocol_address: 0x%x",
			askGetArProFromArpmsg(arp_ptr));
	asLogMessage("length_of_hardware_address: %u",
			askGetArHlnFromArpmsg(arp_ptr));
	asLogMessage("length_of_protocol_address: %u",
			askGetArPlnFromArpmsg(arp_ptr));
	asLogMessage("ARP_opcode: %u",
			askGetOpcodeFromArpmsg(arp_ptr));

	// Need to take care of the memory...
	tmp_ptr = askGetArShaFromArpmsg(arp_ptr);
	asLogMessage("sender_hardware_address: %s", tmp_ptr);
	free(tmp_ptr);

	tmp_ptr = askGetArSipFromArpmsg(arp_ptr);
	asLogMessage("sender_IP_address: %s", tmp_ptr);
	free(tmp_ptr);

	tmp_ptr = askGetArThaFromArpmsg(arp_ptr);
	asLogMessage("target_hardware_address: %s", tmp_ptr);
	free(tmp_ptr);

	tmp_ptr = askGetArTipFromArpmsg(arp_ptr);
	asLogMessage("target_IP_address: %s", tmp_ptr);
	free(tmp_ptr);

        asLogMessage("==================================");
        asLogMessage("End dumping(2) the kernel arpmsg");
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askCheckMacBroadcast
// Description  : check if the MAC address is a broadcast address
//
// Inputs       : mac_ptr - pointer to the mac address in askRelayMessage format
// Outputs      : int 0 - false, 1 - true
// Dev          : daveti

int askCheckMacBroadcast(char *mac_ptr)
{
	if ((strcasecmp(mac_ptr, ARPSEC_MAC_BROAD_STRING_FF) == 0) ||
		(strcasecmp(mac_ptr, ARPSEC_MAC_BROAD_STRING_00) == 0))
	{
		return 1;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Function     : askGetSystemName
// Description  : get the system name ('sys'+hostname) based on IP dot string
//
// Note		: gprolog does not allow '.' in the statement. Will replace all the
//		: '.' into '_' here!
// Inputs       : ip_ptr - IP dot string pointer - char *
// Outputs      : sys - char *
// Dev          : daveti

char * askGetSystemName(char *ip_ptr)
{
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	char hbuf[NI_MAXHOST] = {0};
	int rtn;
	int i;
	char *sys;

	// Construct the socket address
	inet_pton(AF_INET, ip_ptr, &(sa.sin_addr));

	// Get the hostname from the IP
	rtn = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD);
	if (rtn != 0)
		asLogMessage("Error on getnameinfo [%s]", gai_strerror(rtn));
	else
		asLogMessage("Info - got the remote hostname [%s] for IP [%s]",
				hbuf, ip_ptr);

	// Construct the system name string
	sys = (char *)malloc(ARPSEC_HOSTNAME_LEN);
        snprintf(sys, ARPSEC_HOSTNAME_LEN, "%s", "sys");
	rtn = strlen("sys");

	for (i = 0; (hbuf[i] != '\0') && (ARPSEC_HOSTNAME_LEN - i > 1); i++)
	{
		if (hbuf[i] != '.')
			sys[rtn + i] = hbuf[i];
		else
			sys[rtn + i] = '_';
	}
	sys[rtn + i] = '\0';
		
	return sys;
}

////////////////////////////////////////////////////////////////////////////////
// Function     : askConvertArpmsg
// Description  : convert a kernel arpmsg to a relay message
//
// Inputs       : arp_ptr - arpmsg pointer
// Outputs      : msg - askRelayMessage pointer
// Dev		: daveti
 
askRelayMessage * askConvertArpmsg( arpsec_arpmsg *arp_ptr) {

	askRelayMessage *msg = NULL;
	char *tmp_ptr;

	// Validate this ARP msg from kernel
	if ( askValidateArpmsg(arp_ptr) == -1) {
		asLogMessage("Error on invalid ARP/RARP msg from the kernel");
		askDumpArpmsg(arp_ptr);
	} else {
		// daveti: debug
		askDumpArpmsg(arp_ptr);
		askDumpArpmsg2(arp_ptr);

		// Allocate the buffer for msg
		msg = askAllocateBuffer(&msg);

		// Make a askRelayMessage
		// NOTE: treat the msg->source as the hostname
		// with the prefix 'sys' - look into askSetupLocalInfo
		// for detailes...

		switch (askGetOpcodeFromArpmsg(arp_ptr))
		{
			case ARPSEC_ARPOP_REQUEST:
				msg->op = RFC_826_ARP_REQ;
				msg->sndr = askGetArShaFromArpmsg(arp_ptr);
				tmp_ptr = askGetArThaFromArpmsg(arp_ptr);
				if (askCheckMacBroadcast(tmp_ptr) == 1)
				{
					msg->dest = strdup(HW_ADDR_ANY);
					free(tmp_ptr);
				}
				else
					msg->dest = tmp_ptr;
				msg->target.network = askGetArTipFromArpmsg(arp_ptr);
				break;

			case ARPSEC_ARPOP_REPLY:
				msg->op = RFC_826_ARP_RES;
				// Get the msg->source
				tmp_ptr = askGetArSipFromArpmsg2(arp_ptr);
				msg->source = askGetSystemName(tmp_ptr);
				free(tmp_ptr);
				msg->sndr = askGetArShaFromArpmsg(arp_ptr);
				msg->dest = askGetArThaFromArpmsg(arp_ptr);
				// Duplicate the sender's info as the target!
				msg->target.network = askGetArSipFromArpmsg(arp_ptr);
				msg->binding.media = askGetArShaFromArpmsg(arp_ptr);
				break;

			case ARPSEC_ARPOP_RREQUEST:
				msg->op = RFC_903_ARP_RREQ;
                                msg->sndr = askGetArShaFromArpmsg(arp_ptr);
                                msg->dest = askGetArThaFromArpmsg(arp_ptr);
                                msg->target.media = askGetArThaFromArpmsg(arp_ptr);
				break;

			case ARPSEC_ARPOP_RREPLY:
				msg->op = RFC_903_ARP_RRES;
				// Get the msg->source
				tmp_ptr = askGetArSipFromArpmsg2(arp_ptr);
				msg->source = askGetSystemName(tmp_ptr);
				free(tmp_ptr);
                                msg->sndr = askGetArShaFromArpmsg(arp_ptr);
                                msg->dest = askGetArThaFromArpmsg(arp_ptr);
                                // Duplicate the sender's info as the target!
                                msg->target.media = askGetArThaFromArpmsg(arp_ptr);
                                msg->binding.network = askGetArTipFromArpmsg(arp_ptr);
				break;

			default:
				asLogMessage("Error on unsupported ARP opcode");
				askReleaseBuffer(msg);
				msg = NULL;
				break;
		}
	}

	return msg;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askSetupLocalInfo
// Description  : Setup a bunch of the local information
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int askSetupLocalInfo(void)
{
	char *tmp_ptr;
	char *ptr;
	int rtn;
	int length;
	int i;
	char tmp_buff[ARPSEC_GENERAL_BUFF_LEN] = {0};
	struct ifaddrs *ifAddrStruct = NULL;
	struct ifaddrs *ifAddrPtr = NULL;
	void *tmpAddrPtr = NULL;
	struct ifconf ifc = {0};
	struct ifreq *ifr = NULL;
	struct ifreq *item;
	int sock;
	char buf[8192] = {0};
	

	// Setup the local system name (hostname)
	if (gethostname(tmp_buff, ARPSEC_GENERAL_BUFF_LEN) == -1)
	{
		asLogMessage("Error on gethostname [%s]", strerror(errno));
		return -1;
	}

	tmp_ptr = (char *)malloc(ARPSEC_HOSTNAME_LEN);
	snprintf(tmp_ptr, ARPSEC_HOSTNAME_LEN, "%s%s", "sys", tmp_buff);
	ascSetLocalSystem(tmp_ptr);

	memset(tmp_buff, 0, ARPSEC_GENERAL_BUFF_LEN);

	// Setup the local IP address
	// getifaddrs() system call is used here.

	if (getifaddrs(&ifAddrStruct) == -1)
	{
		asLogMessage("Error on getifaddrs [%s]", strerror(errno));
		return -1;
	}

	for (ifAddrPtr = ifAddrStruct; ifAddrPtr != NULL; ifAddrPtr = ifAddrPtr->ifa_next)
	{
		if (strcasecmp(ifAddrPtr->ifa_name, ARPSEC_IF_NAME) == 0)
		{
			// Got the interface we need to handle
			if (ifAddrPtr->ifa_addr->sa_family == AF_INET)
			{
				// Got the IPv4 address for this interface
				tmpAddrPtr=&((struct sockaddr_in *)ifAddrPtr->ifa_addr)->sin_addr;
				inet_ntop(AF_INET, tmpAddrPtr, tmp_buff, ARPSEC_GENERAL_BUFF_LEN);
				asLogMessage("Info - got IPv4 address for %s: %s",
						ARPSEC_IF_NAME, tmp_buff);
				break;
			}
		}
	}

	freeifaddrs(ifAddrStruct);
				
	if (tmp_buff[0] == '\0')
	{
		asLogMessage("Error on finding an IPv4 address for interface %s", ARPSEC_IF_NAME);
		return -1;
	}
	
	// Convert the dot string into arpsec IP string
	tmp_ptr = (char *)malloc(ARPSEC_IP_ADDRESS_LEN);
	rtn = snprintf(tmp_ptr, ARPSEC_IP_ADDRESS_LEN, "%s", "net");
	
	// Update the starting pointer
	ptr = tmp_ptr + rtn;
	// Update the valid length of the buffer
	length = ARPSEC_IP_ADDRESS_LEN - rtn;

	// Construct the arpsec IP address string
	i = 0;
	while ((tmp_buff[i] != '\0') && (length > 1))
	{
		if (tmp_buff[i] != '.')
			*ptr = tmp_buff[i];
		else
			*ptr = '_';

		// Update the vars
		ptr++;
		i++;
		length--;
	}
	*ptr = '\0';
	ascSetLocalNet(tmp_ptr);

	memset(tmp_buff, 0, ARPSEC_GENERAL_BUFF_LEN);

	// Setup the local MAC address
	// ioctl() system call is used here.
	
	// Open the socket for ioctl
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		asLogMessage("Error on socket [%s]", strerror(errno));
		return -1;
	}

	// Get all the interfaces available
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
	{
		asLogMessage("Error on ioctl with SIOCGIFCONF [%s]", strerror(errno));
		return -1;
	}

	// Go thru all the interfaces
	ifr = ifc.ifc_req;
	rtn = ifc.ifc_len / sizeof(struct ifreq);

	for (i = 0; i < rtn; i++)
	{
		item = &ifr[i];
		if (strcasecmp(item->ifr_name, ARPSEC_IF_NAME) == 0)
		{
			// Get the MAC for this interface
			if (ioctl(sock, SIOCGIFHWADDR, item) < 0)
			{
				asLogMessage("Error on ioctl with SIOCGIFHWADDR [%s]", strerror(errno));
				close(sock);
				return -1;
			}

			// Use '_' directly instead of ':' for the MAC construction
			snprintf(tmp_buff, ARPSEC_GENERAL_BUFF_LEN, "%x_%x_%x_%x_%x_%x",
				(unsigned char)item->ifr_hwaddr.sa_data[0],
				(unsigned char)item->ifr_hwaddr.sa_data[1],
				(unsigned char)item->ifr_hwaddr.sa_data[2],
				(unsigned char)item->ifr_hwaddr.sa_data[3],
				(unsigned char)item->ifr_hwaddr.sa_data[4],
				(unsigned char)item->ifr_hwaddr.sa_data[5]);
			asLogMessage("Info - got MAC address for %s: %s",
					ARPSEC_IF_NAME, tmp_buff);
			break;
		}
	}

	close(sock);

        // Convert the colon string into arpsec IP string
        tmp_ptr = (char *)malloc(ARPSEC_MAC_ADDRESS_LEN);
        snprintf(tmp_ptr, ARPSEC_MAC_ADDRESS_LEN, "%s%s", "media", tmp_buff);
	ascSetLocalMedia(tmp_ptr);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askAllocateBuffer
// Description  : Allocate a relay message buffer
//
// Inputs       : buf - reference to point for allocated buffer
// Outputs      : buffer or NULL if failure
 
askRelayMessage * askAllocateBuffer( askRelayMessage **buf ) {

    // Allocate and return buffer
    *buf = malloc( sizeof(askRelayMessage) ) ;
    memset( *buf, 0x0, sizeof(askRelayMessage) );
    return( *buf );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askReleaseBuffer
// Description  : Release the buffer received from a previous request
//
// Inputs       : buf - the buffer to release
// Outputs      : 0 if successful, -1 if failure 

int askReleaseBuffer( askRelayMessage *buf ) {

    // Release, return successfully
    if ( buf == NULL ) return( 0 );
    if ( buf->source != NULL ) free( buf->source );
    if ( buf->sndr != NULL ) free( buf->sndr );
    if ( buf->dest != NULL ) free( buf->dest );
    if ( (buf->op == RFC_826_ARP_REQ) || (buf->op == RFC_826_ARP_RES) ) {
	if (  buf->target.network != NULL ) free( buf->target.network );
	if (  buf->binding.media != NULL ) free( buf->binding.media );
    } else {
	if (  buf->target.media != NULL ) free( buf->target.media );
	if (  buf->binding.network != NULL ) free( buf->binding.network );
    }
    free( buf );
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askToNetString
// Description  : convert the raw address to a string
//
// Inputs       : addr - the address to convert
//                str - the string to convert to
//                len - the length of the string
// Outputs      : 0 if successful, -1 if failure 

char * askToNetString( unsigned long addr, char *str, int len ) {
   
    // Encode to PROLOG-freindly value
    char *ptr = (char *)&addr;
    snprintf( str, len, "net%u_%u_%u_%u", (unsigned char)ptr[0], (unsigned char)ptr[1], 
	    (unsigned char)ptr[2], (unsigned char)ptr[3] );
    return( str );

}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askToMediaString
// Description  : convert the raw address to a string
//
// Inputs       : media - the address to convert
//                str - the string to convert to
//                len - the length of the string
// Outputs      : 0 if successful, -1 if failure 

char * askToMediaString( char *media, char *str, int len ) {
   
    // Encode to PROLOG-freindly value
    snprintf( str, len, "media%x_%x_%x_%x_%x_%x", (unsigned char)media[0], (unsigned char)media[1], 
	    (unsigned char)media[2], (unsigned char)media[3], 
	    (unsigned char)media[4], (unsigned char)media[5] );
    return( str );

}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askMessageToString
// Description  : generate a string containing the contents of message
//
// Inputs       : msg - place to put the message
//		  str - string buffer to place this in
//                len - maximum legth of string
// Outputs      : pointer to the message or NULL if failure

char * askMessageToString( askRelayMessage *msg, char *str, int len ) {

    // Format string and return
    if ( (msg->op == RFC_826_ARP_RES) || (msg->op == RFC_903_ARP_RRES) ) {
	snprintf( str, len, "AS Msg [%s,src=%s,sdn=%s,dst=%s,addr=%s,bind=%s", askOpCodeStrings[msg->op], 
		msg->source, msg->sndr, msg->dest, msg->target.network, msg->binding.media );
    } else {
	snprintf( str, len, "AS Msg [%s,sdn=%s,dst=%s,addr=%s", askOpCodeStrings[msg->op], 
		msg->sndr, msg->dest, msg->target.network );
    }
    return( str );

}

//
// Simluation Methods

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askSetupSimulation
// Description  : Setup a bunch of the simluation information
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure 

int askSetupSimulation( void ) {

    // Local variables
    int i;

    // For each simulated system
    for ( i=0; i<MAX_SIM_VALS; i++ ) {

	// Pick some random system information
	snprintf( askSimSystems[i], 128, "sys%d", as_random(0xffff) );
	gcry_randomize( &askSimIPs[i], sizeof(unsigned long), GCRY_STRONG_RANDOM );
	askToNetString( askSimIPs[i], askSimIPStrings[i], 128 );
	gcry_randomize( askSimEths[i], 6, GCRY_STRONG_RANDOM );
	askToMediaString( askSimEths[i], askSimEthStrings[i], 128 );
	asLogMessage( "Creating simulated system %s (net=%s,med=%s)", askSimSystems[i], 
		askSimIPStrings[i], askSimEthStrings[i] );

    }

    // Set the local values to the first ones
    ascSetLocalSystem( askSimSystems[0] );
    ascSetLocalNet( askSimIPStrings[0] );
    ascSetLocalMedia( askSimIPStrings[0] );

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : askGenerateSimMessage
// Description  : generate a simulated message for processing
//
// Inputs       : msg - place to put the message
// Outputs      : pointer to the message or NULL if failure

askRelayMessage * askGenerateSimMessage( void ) {

    // Local variables
    int op, sender, lookingfor;
    askRelayMessage *msg;

    // Allocate the message, randomly select the message fields
    askAllocateBuffer( &msg );
    op = as_random( 4 );
    sender = as_random( MAX_SIM_VALS );
    do { // Make sure not asking for own bidings
       lookingfor = as_random( MAX_SIM_VALS );
    } while (sender == lookingfor);

    // Setup some basic message structures
    msg->op = op;
    msg->sndr = strdup( askSimEthStrings[sender] ); 
    msg->dest = strdup( HW_ADDR_ANY );

    // Figure out which message we are sending
    switch (op) {
    
	case RFC_826_ARP_REQ:    // ARP Request
	msg->target.network = strdup( askSimIPStrings[lookingfor] );
	break;

	case RFC_826_ARP_RES:    // ARP Response
	msg->source = strdup( askSimSystems[lookingfor] );
	msg->target.network = strdup( askSimIPStrings[lookingfor] );
	msg->binding.media = strdup( askSimEthStrings[lookingfor] );
	break;

	case RFC_903_ARP_RREQ:   // ARP Reverse Request
	msg->target.media = strdup( askSimEthStrings[lookingfor] );
	break;

	case RFC_903_ARP_RRES:   // ARP Reverse Response
	msg->source = strdup( askSimSystems[lookingfor] );
	msg->target.media = strdup( askSimEthStrings[lookingfor] );
	msg->binding.network = strdup( askSimIPStrings[lookingfor] );
	break;

	default:
	    asLogMessage( "Bad simulated packet, aborting [%d]", op );
	    exit( -1 );
    }

    // Return the message 
    return( msg );
}

