#ifndef AsKrnRelay_INCLUDED
#define AsKrnRelay_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsKrnRelay.h
//  Description   : The AsKrnRelay module implements the interface inbetween
//                  the kernel and the daemon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 09:33:11 EDT 2013
//
//  daveti  : Jul 30, 2013
//

// Includes

// Project Includes
#include "AsDefs.h"

// Type definitions
#define ASKRN_UNKNOWN	    0  // Unknown operating mode
#define ASKRN_SIMULATION    1  // Simluation of the kernel operation
#define ASKRN_RELAY	    2  // Interaction with the kernel directly

// Linux Kernel ARP definitions
#define ARPSEC_DEBUGFS			"/sys/kernel/debug"
#define ARPSEC_RELAY_FILE		"/sys/kernel/debug/arpsec_cpu"
#define ARPSEC_RELAY_FILE_BUFF		(strlen(ARPSEC_RELAY_FILE)+2)
#define ARPSEC_ETH_ALEN			6  // Length of ethernet (hardware) address
#define ARPSEC_IPV4_ALEN		4  // Length of IPv4 address
#define ARPSEC_ARP_16BIT		2  // 16-bit used by ARP
#define ARPSEC_MAX_NUM_OF_CPUS		12 // Max number of CPUs
#define ARPSEC_PKG_SIZE			28 // Size of ARP pkg
#define ARPSEC_RELAY_BUFFLEN		280// Length of the buffer to read from relay
#define ARPSEC_IP_ADDRESS_LEN		sizeof("net255_255_255_255")
#define ARPSEC_MAC_ADDRESS_LEN		sizeof("mediaff_ff_ff_ff_ff_ff")
#define ARPSEC_MAC_BROAD_STRING_FF	"mediaff_ff_ff_ff_ff_ff"
#define ARPSEC_MAC_BROAD_STRING_00	"media0_0_0_0_0_0"
#define ARPSEC_HOSTNAME_LEN		128
#define ARPSEC_IF_NAME			"eth1"	// For Fedora, this may be "em1", For Ubuntu, it may be "eth1", others are "eth0"
#define ARPSEC_GENERAL_BUFF_LEN		128

// Linux Kernel ARP opcode
// #include <linux/if_arp.h>
#define ARPSEC_ARPOP_REQUEST	1
#define ARPSEC_ARPOP_REPLY	2
#define ARPSEC_ARPOP_RREQUEST	3
#define ARPSEC_ARPOP_RREPLY	4

// Linux Kernel ARP/RARP msg data structure
typedef struct _arpmsg {
        unsigned char 	ar_hrd[ARPSEC_ARP_16BIT];         /* format of hardware address   */
        unsigned char	ar_pro[ARPSEC_ARP_16BIT];         /* format of protocol address   */
        unsigned char   ar_hln;         	/* length of hardware address   */
        unsigned char   ar_pln;         	/* length of protocol address   */
        unsigned char	ar_op[ARPSEC_ARP_16BIT];          /* ARP opcode (command)         */
        unsigned char           ar_sha[ARPSEC_ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[ARPSEC_IPV4_ALEN];              /* sender IP address            */
        unsigned char           ar_tha[ARPSEC_ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[ARPSEC_IPV4_ALEN];              /* target IP address            */
} arpsec_arpmsg;

typedef struct _arpsec_rlmsg {
	arpsec_arpmsg	arpsec_arp_msg;
	void		*arpsec_dev_ptr;
} arpsec_rlmsg;

// Add support for global relay queue
// to handle multiple msgs from the kernel
// Sep 13, 2013
// daveti
#define ARPSEC_RELAY_QUEUE_MSG_NUM	200
#define ARPSEC_RELAY_QUEUE_SIZE		(sizeof(arpsec_rlmsg)*ARPSEC_RELAY_QUEUE_MSG_NUM)


//
// Relay Queue related methods

// Init the global relay queue
void askInitRelayQueue(void);

// Add msgs into the queue
int askAddMsgIntoRelayQueue(void *msg, int len);

// Get the head msg from the queue
arpsec_rlmsg *askGetHeadMsgFromRelayQueue(void);

// Remove the head msg from the queue
void askDelHeadMsgFromRelayQueue(void);

// Get the number of the msgs in the queue
int askGetMsgNumInRelayQueue(void);

//
// Module methods
	
// Initialize the relay code (mode is sym vs. kern)
int askInitRelay( int mode );

//  Close the relay 
int askShutdownRelay( void );

// Get a reference to the relay file handle (used for selecting)
int askGetRelayHandle( void );
void askGetRelayHandle2( void );
int * askGetRelayHandle3( void );

// Get the net device pointer from kernel rlmsg
void *askGetDevPtrFromRlmsg(arpsec_rlmsg *rlmsg_ptr);

// Get format of hardware address from kernel arpmsg
int askGetArHrdFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get format of protocol address from kernel arpmsg
int askGetArProFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get length of hardware address from kernel arpmsg
int askGetArHlnFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get length of protocol address from kernel arpmsg
int askGetArPlnFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get ARP opcode from kernel arpmsg
int askGetOpcodeFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get sender hardware address from kernel arpmsg
char * askGetArShaFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get sender IP address from kernel arpmsg
char * askGetArSipFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get target hardware address from kernel arpmsg
char * askGetArThaFromArpmsg(arpsec_arpmsg *arp_ptr);

// Get target IP address from kernel arpmsg
char * askGetArTipFromArpmsg(arpsec_arpmsg *arp_ptr);

// Dump a kernel arpmsg
void askDumpArpmsg(arpsec_arpmsg *arp_ptr);

// Dump a kernel arpmsg
void askDumpArpmsg2(arpsec_arpmsg *arp_ptr);

// Check if the MAC is a broadcast address
int askCheckMacBroadcast(char *mac_ptr);

// Validate a kernel arpmsg
int askValidateArpmsg(arpsec_arpmsg *arp_ptr);

// Setup a bunch of the local information
int askSetupLocalInfo( void );

// Convert a kernel arpmsg into askRelayMessage
askRelayMessage * askConvertArpmsg(arpsec_rlmsg *rlmsg_ptr);

// Get system name ('sys'+hostname) based on the IP dot string
char * askGetSystemName(char *ip_ptr);

// Get the next message off the relay, or nothing if non available
askRelayMessage * askGetNextMessage( void );

// send a message to the kernel
int askSubmitMessage( askRelayMessage *buf );

// Allocate a relay message buffer
askRelayMessage * askAllocateBuffer( askRelayMessage **buf );

// Release the buffer received from a previous request
int askReleaseBuffer( askRelayMessage *buf );

// convert the raw address to a string
char * askToNetString( unsigned long addr, char *str, int len );

// convert the raw address to a string
char * askToMediaString( char *media, char *str, int len );

// generate a string containing the contents of message
char * askMessageToString( askRelayMessage *msg, char *str, int len );

//
// Simulation Methods

// Setup a bunch of the simluation information
int askSetupSimulation( void );

// generate a simulated message for processing
askRelayMessage * askGenerateSimMessage( void ); 


#endif
