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

#define ARPSEC_RELAY_FILE	"/sys/kernel/debug/arpsec_cpu"
#define ARPSEC_ETH_ALEN		6  // Length of ethernet (hardware) address
#define ARPSEC_IPV4_ALEN	4  // Length of IPv4 address
#define ARPSEC_ARP_16BIT	2  // 16-bit used by ARP

typedef struct _arpmsg {
        unsigned char 	ar_hrd[ARPSEC_ARP_16BIT];         /* format of hardware address   */
        unsgined char	ar_pro[ARPSEC_ARP_16BIT];         /* format of protocol address   */
        unsigned char   ar_hln;         	/* length of hardware address   */
        unsigned char   ar_pln;         	/* length of protocol address   */
        unsigned char	ar_op[ARPSEC_ARP_16BIT];          /* ARP opcode (command)         */
        unsigned char           ar_sha[ARPSEC_ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[ARPSEC_IPV4_ALEN];              /* sender IP address            */
        unsigned char           ar_tha[ARPSEC_ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[ARPSEC_IPV4_ALEN];              /* target IP address            */
} arpsec_arpmsg;


//
// Module methods
	
// Initialize the relay code (mode is sym vs. kern)
int askInitRelay( int mode );

//  Close the relay 
int askShutdownRelay( void );

// Get a reference to the relay file handle (used for selecting)
int askGetRelayHandle( void );

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
