#ifndef AsDefs_INCLUDED
#define AsDefs_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsDefs.h
//  Description   : These are the basic data types for the arpsec deamon.
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 13:06:54 EDT 2013
//  Dev	    : daveti Aug 21 2013
//

// Includes
#include <time.h>
#include <stdlib.h>

//
// Defines
#define MAX_MEDADDR_LENGTH 128
#define MAX_NETADDR_LENGTH 128
#define HW_ADDR_ANY "HWANY"

//
// Type definitions

typedef time_t	AsTime; 			// The time component of our logic (T)
typedef char *	AsSystem;			// The system set of the logic (S)
typedef char *  AsMediaAddress;		// The media (MAC) addresses
typedef	char *  AsNetworkAddress;	// The network (IP) addresses

// ARP Definitions
typedef enum {
    RFC_826_ARP_REQ = 0,	// ARP Request
    RFC_826_ARP_RES = 1,	// ARP Response
    RFC_903_ARP_RREQ = 2,	// ARP Reverse Request
    RFC_903_ARP_RRES = 3,	// ARP Reverse Response
} ArpOpcode;

// Ask Message Type
typedef struct {
    AsSystem		source;	// This is the (suspected) source system
    AsMediaAddress 	sndr;	// The sender of the message
    AsMediaAddress 	dest;	// The destination HW address of message
    AsNetworkAddress	sndr_net;	// daveti: save the sender's IP here
    AsNetworkAddress	dest_net;	// daveti: save the target's IP here
    unsigned		op;	// The message type (ArpOpcode)
    union {
	AsNetworkAddress    network;	// Network address to lookup
	AsMediaAddress	    media;	// Media address to reverse lookup
    } target;
    union {
	AsNetworkAddress    network;	// Network address to bind to
	AsMediaAddress	    media;	// Media address to bind to
    } binding;

    void	*dev_ptr;	// daveti: device ptr from kernel
} askRelayMessage;

// A random function
#define as_random(x) (int)((float)rand()/((float)RAND_MAX)*((float)x))

//
// Global data

extern char *askOpCodeStrings[4]; // Message type strings

#endif
