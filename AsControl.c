////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsControl.cpp
//  Description   : The AsControl module implements a shim for the system
//                  trust validation for the arpsec deamon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 10:25:00 EDT 2013

//
// Includes
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

// Project Includes
#include "AsControl.h"
#include "AsLogic.h"
#include "AsKrnRelay.h"
#include "AsLog.h"
#include "AsTMeasure.h"

// Defines
#define SELECT_WAIT_PERIOD 1

// Module data
int	ascControlDone = 0;
char	*ascLocalSystem = NULL;	    // The name of the local system
char	*ascLocalNet = NULL;	    // The local network address name
char	*ascLocalMedia = NULL;	    // The local media address name

//
// Module functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalSystem
// Description  : Setup the local infomation associated with this process
//
// Inputs       : sys - the local system name
// Outputs      : 0 if successful, -1 if not

void ascSetLocalSystem( char *sys ) {
    // Set value and return
    ascLocalSystem = sys;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalNet
// Description  : Setup the local infomation associated with this process
//
// Inputs       : net - the local network address
// Outputs      : 0 if successful, -1 if not

void ascSetLocalNet( char *net) {
    // Set value and return
    ascLocalNet = net;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalMedia
// Description  : Setup the local infomation associated with this process
//
// Inputs       : med - the local media address
// Outputs      : 0 if successful, -1 if not

void ascSetLocalMedia(  char *med ) {
    // Set value and return
    ascLocalMedia = med;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascPendingNetworkBinding
// Description  : determine whether this response is in relation to prev request
//
// Inputs       : addr - the address to check
// Outputs      : 0 if successful, -1 if failure

int ascPendingNetworkBinding( AsNetworkAddress addr ) {
    // For now, just return pending for everything
    asLogMessage( "PENDING NETWORK BINDING: UNIMPLEMNTED, returning TRUE" );
    return( 1 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascPendingMediaBinding
// Description  : determine whether this response is in relation to prev request
//
// Inputs       : addr - the address to check
// Outputs      : 0 if successful, -1 if failure

int ascPendingMediaBinding( AsMediaAddress addr )  {
    // For now, just return pending for everything
    asLogMessage( "PENDING MEDIA BINDING: UNIMPLEMNTED, returning TRUE" );
    return( 1 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpRequest
// Description  : process a received ARP request message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure

int ascProcessArpRequest( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    AsTime now = time(NULL);
    char media[MAX_MEDADDR_LENGTH];
    AsMediaAddress med = media;

    // Do a quick sanity check
    if ( msg->op != RFC_826_ARP_REQ ) {
	asLogMessage( "ascProcessArpRequest: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If the local interface is the one that we are looking for
    if ( strcmp( msg->target.network, ascLocalNet ) == 0 ) {

	// TODO: implement the arp response tickle of the kernel when we have it
	asLogMessage( "ascProcessArpRequest: UNIMPLEMNTED ARP RESPONSE, waiting for kernel" );
	ret = -1;


    } else {

	// Check to see if we have a good binding for this
	asStartMetricsTimer();
	if ( aslFindValidMediaBinding( msg->target.network, med, now ) )  {
	    asLogMessage( "Found good ARP REQ binding {%s->%s]", msg->target.network, med );
	} else {
	    asLogMessage( "Failed to find good ARP REQ binding [%s]", msg->target.network );
	}
	asStopMetricsTimer( "ARP Binding" );

    }

    // Return the return code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpResponse
// Description  : process a received ARP response message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure

int ascProcessArpResponse( askRelayMessage *msg ) {

    //Local variables
    AsTime now = time(NULL);

    // Do a quick sanity check
    if ( msg->op != RFC_826_ARP_RES ) {
	asLogMessage( "ascProcessArpResponse: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If this was a response we were looking for
    if ( ascPendingNetworkBinding(msg->target.network) ) {

	// Check the source system
	if ( ! aslSystemTrusted(msg->source, now) )  {

	    // Go attest the system
	    if( astAttestSystem(msg->source) ) {
		asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES", 
			msg->source, now );
		return( -1 );
	    }

	    // Add the attestation time to the logic
	    aslAddTrustStatement( msg->source, now );
	}

	// Ok, now trusted, add binding statement
	asStartMetricsTimer();
	aslAddBindingStatement( msg->source, msg->target.network, msg->binding.media, now );
	asStopMetricsTimer( "ARP add binding ");
	asLogMessage( "Successfully processed ARP RES [%s->%s]", msg->target.media, msg->binding.network );

    } else {

	// Check the source system
	if ( aslSystemTrusted(msg->source, now) )  {

	    // Ok, now trusted, add binding statement
	    aslAddBindingStatement( msg->source, msg->target.network, msg->binding.media, now );
	    asLogMessage( "Successfully processed foriegn ARP RES [%s->%s]", 
		    msg->target.media, msg->binding.network );

	} else {

	    // Foreign IP from untrusted system
	    asLogMessage( "ascProcessArpResponse: ignoring ARP RES for foreign IP [%s]", 
		    msg->target.network );
	}


    }

    // Otherwise this is intended for somebody else
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessRArpRequest
// Description  : process a received RARP request message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure

int ascProcessRArpRequest( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    AsTime now = time(NULL);
    char network[MAX_NETADDR_LENGTH];
    AsNetworkAddress net = network;

    // Do a quick sanity check
    if ( msg->op != RFC_903_ARP_RREQ ) {
	asLogMessage( "ascProcessRArpRequest: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If the local interface is the one that we are looking for
    if ( strcmp( msg->target.media, ascLocalMedia ) == 0 ) {

	// TODO: implement the arp response tickle of the kernel when we have it
	asLogMessage( "ascProcessArpRequest: UNIMPLEMNTED RARP RESPONSE, waiting for kernel" );
	ret = -1;

    } else {

	// Check to see if we have a good binding for this
	asStartMetricsTimer();
	if ( aslFindValidNetworkBinding( net, msg->target.media, now ) )  {
	    asLogMessage( "Found good ARP binding {%s->%s]", msg->target.media, net );
	} else {
	    asLogMessage( "Failed to find good RARP REQ binding [%s]", msg->target.media );
	}
	asStopMetricsTimer( "RARP Binding" );

    }

    // Return the processing code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessRArpResponse
// Description  : process a received RARP response message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure

int ascProcessRArpResponse( askRelayMessage *msg ) {

    //Local variables
    AsTime now = time(NULL);

    // Do a quick sanity check
    if ( msg->op != RFC_903_ARP_RRES ) {
	asLogMessage( "ascProcessRArpResponse: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If this was a response we were looking for
    if ( ascPendingMediaBinding(msg->target.media) ) {

	// Check the source system
	if ( ! aslSystemTrusted(msg->source, now) )  {

	    // Go attest the system
	    if( astAttestSystem(msg->source) ) {
		asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES", 
			msg->source, now );
		return( -1 );
	    }

	    // Add the attestation time to the logic
	    aslAddTrustStatement( msg->source, now );
	}

	// Now add the binding statement
	asStartMetricsTimer();
	aslAddBindingStatement( msg->source, msg->binding.media, msg->target.network, now );
	asLogMessage( "Successfully processed RARP RES [%s->%s]", msg->target.network, msg->binding.media );
	asStopMetricsTimer( "RARP add binding ");

    } else {

	// Check the source system
	if (  aslSystemTrusted(msg->source, now) )  {

	    // Now add the binding statement
	    aslAddBindingStatement( msg->source, msg->binding.media, msg->target.network, now );
	    asLogMessage( "Successfully processed foreign RARP RES [%s->%s]", 
		    msg->target.network, msg->binding.media );
	} else {

	    // Ignore message
	    asLogMessage( "ascProcessArpResponse: ignoring ARP REQ for foreign IP [%s]", 
		    msg->target.network );
	}
    }

    // Otherwise this is intended for somebody else
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessMessage
// Description  : process a received ARP message
//
// Inputs       : msg - received message
// Outputs      : pointer to the message or NULL if failure

int ascProcessMessage( askRelayMessage *msg ) {

    // Log the fact that we got the message
    int ret;
    char buf[256];
    asLogMessage( "Processing ARP from kernel [%s]", askMessageToString(msg,buf, 256) );


    // If we are the soruce, just ignore
    if ( strcmp(msg->sndr, ascLocalMedia) == 0 ) {
	asLogMessage( "Ignoring message sent mby local stack [%s]", askMessageToString(msg,buf, 256) );
	return( 0 );
    }

    // Figure out which message we are sending
    switch (msg->op) {
    
	case RFC_826_ARP_REQ:    // ARP Request
	ret = ascProcessArpRequest( msg );
	break;

	case RFC_826_ARP_RES:    // ARP Response
	ret = ascProcessArpResponse( msg );
	break;

	case RFC_903_ARP_RREQ:   // ARP Reverse Request
	ret = ascProcessRArpRequest( msg );
	break;

	case RFC_903_ARP_RRES:   // ARP Reverse Response
	ret = ascProcessRArpResponse( msg );
	break;

	default:
	asLogMessage( "Unknown ARP packet, aborting [%d]", msg->op );
	exit( -1 );
    }

    // Return the return code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascControlLoop
// Description  : This is the control loop used for the arpsec deamon
//
// Inputs       : mode - simulate or run normally
// Outputs      : 0 if successful, -1 if not

int ascControlLoop( int mode ) {
    
    // Local variables
    int rval, nfds, sim, fh;
    struct timeval next;
    fd_set rdfds, wrfds;
    askRelayMessage *msg;
#ifdef UNIT_TESTING
    int rnd;
#endif

    // Setup the signal handler 
    signal( SIGINT, ascSigIntHandler );
    signal( SIGHUP, ascSigHupHandler );

    // Intalialize all of the subsystems
    sim = (mode) ? ASKRN_SIMULATION : ASKRN_RELAY;
    if ( aslInitLogic() || (askInitRelay(sim)) ) {

	// Log and error out of processing
	asLogMessage( "arpsec deamon initalization failed, aborting.\n" );
	return( -1 );
    }

    // Loop until done
    ascControlDone = 0;
    while ( !ascControlDone ) {

	// Setup the select wait
	nfds = 0;
	FD_ZERO( &rdfds );
	FD_ZERO( &wrfds );

	// Set the wait period
	next.tv_sec = SELECT_WAIT_PERIOD;
	next.tv_usec =  0 ; 

	// If the relay has a file handle, use it
	if ( (fh=askGetRelayHandle()) != -1 ) {
	    FD_SET( fh, &wrfds );
	    printf( "Got file handle\n" );
	    nfds = fh+1;
	}
							
	// Do the select, then process the result
	rval = select(nfds, &rdfds, &wrfds, NULL, &next); 
	asLogMessage( "Out of select ..." );
	if ( rval < 0 ) {

	    // We got an error on the select, prepare to bail out
	    asLogMessage( "Error on control loop select, aborting [%s]", strerror(errno) );
	    ascControlDone = 1;
	} 
	
	else if (rval > 0) {

	    // We select the file handle and should process data
	} 

	// Ok, do normal processing
	if ( (msg = askGetNextMessage()) != NULL ) {
	    ascProcessMessage(msg);
	    askReleaseBuffer(msg);
	}

#ifdef UNIT_TESTINAG
	// If unit testing simulating
	if ( mode ) {
	    rnd = as_random(10);
	    if ( rnd > 5 ) {
		testAsLogicInterfaces();
	    }
	}
#endif

    }

    // Close downt the procesing
    askShutdownRelay();
    aslShutdownLogic();

    // Return sucessfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascSigIntHandler
// Description	: process the signal for interrupt
//
// Inputs	: the signal (should be SIGINT)
// Outputs	: none

void ascSigIntHandler( int sig ) {
    ascControlDone = 1;
    asLogMessage( "System received SIGINT signal, processing." );
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascSigHupHandler
// Description	: process the signal for reset (SIGHUP)
//
// Inputs	: the signal (should be SIGHUP)
// Outputs	: none

void ascSigHupHandler( int sig ) {
    asLogMessage( "System received SIGHUP signal, processing." );
    return;
}
















