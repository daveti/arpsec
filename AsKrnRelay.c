////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsKrnRelay.cpp
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

#include <unistd.h>
#include <sys/mount.h>
#include <linux/relay.h>
#include <linux/debugfs.h>

// Project Includes
#include "AsKrnRelay.h"
#include "AsLog.h"
#include "AsControl.h"

// Defines
#define MAX_SIM_VALS 10
#define AS_SIMMSG_FREQ 25
#define PIPE_NAME "input.pipe"
#define MAX_NUM_OF_CPUS 12

// Module local data
int     pipefd;
// daveti: relayfd is used instead of pipefd
int	relayfd[MAX_NUM_OF_CPUS]    = {0};	// Relay file handler array
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

int askShutdownRelay( void ) {

    // Setup intialized, return successfully
    ask_initialized = 0;
    return( 0 );
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
// Function     : askGetNextMessage 
// Description  : Get the next message off the relay, or nothing if non available
//
// Inputs       : none
// Outputs      : buffer if got message, NULL otherwise

askRelayMessage * askGetNextMessage( void ) {

    // Local variables
    askRelayMessage *msg = NULL;

    // If simulating, randomly generate a message (probablistically)
    if ( ask_operating_mode ==  ASKRN_SIMULATION ) {
	    
	if ( as_random(100) < AS_SIMMSG_FREQ ) {
	    msg = askGenerateSimMessage();
	}

    } else {

	// Normal kernel processing here
	asLogMessage( "TODO: implement kernel interface" );

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

int askSubmitMessage( askRelayMessage *buf ) {

    // Return successfully
    return( 0 );
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
























