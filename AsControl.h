#ifndef AsControl_INCLUDED
#define AsControl_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsControl.h
//  Description   : The AsControl module implements the main control loop
//                  and logic for the arpsec deamon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 10:25:00 EDT 2013
//  daveti  : Aug 5, 2013

// Project Includes
#include <stdio.h>
#include "AsDefs.h"

//
// Module methods

// Get the local information associated with this process
char *ascGetLocalNet(void);
char *ascGetLocalMedia(void);

// Setup the local infomation associated with this process
void ascSetLocalSystem( char *sys );
void ascSetLocalNet( char *net );
void ascSetLocalMedia(  char *med );

// Dump all the local infomation for debugging
void ascDumpLocalInfo(void);

// Release the memory used by local info
void ascReleaseMemForLocalInfo(void);

// determine whether this response is in relation to prev request
int ascPendingNetworkBinding( AsNetworkAddress addr );

// determine whether this response is in relation to prev request
int ascPendingMediaBinding( AsMediaAddress addr );

// process a received ARP request message
int ascProcessArpRequest( askRelayMessage *msg );

// process a received ARP response message
int ascProcessArpResponse( askRelayMessage *msg );

// process a received RARP request message
int ascProcessRArpRequest( askRelayMessage *msg );

// process a received RARP response message
int ascProcessRArpResponse( askRelayMessage *msg );

// process a received ARP message
int ascProcessMessage( askRelayMessage *msg );

// This is the control loop used for the arpsec deamon
int ascControlLoop( int mode );

// 
// Signal handers

// process the signal for interrupt (SIGINT)
void ascSigIntHandler( int sig );

// process the signal for reset (SIGHUP)
void ascSigHupHandler( int sig );

#endif
