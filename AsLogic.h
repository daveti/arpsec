#ifndef AsLogic_INCLUDED
#define AsLogic_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsLogic.h
//  Description   : The AsLogic module implements a shim for the logic
//                  program for the arpsec daemnon.
//
//  Author : Patrick McDaniel
//  Created : Sun Mar 24 06:53:30 EDT 2013
//

// Project Includes
#include "AsDefs.h"

//
// Module methods
	
// Initialize the interface to the Logic engine (with parameters)
int aslInitLogic( void );
	
// Shutdown the PL interface
int aslShutdownLogic( void );

//
// Assertion of trust statements
	
// Add a trust statement to the logic
int aslAddTrustStatement( AsSystem s, AsTime t );

// Add a binding statement to the logic
int aslAddBindingStatement( AsSystem s, AsMediaAddress m, AsNetworkAddress n, AsTime t );
	
//
// Logic query methods
	
// Find the valid binding for network address N at time T
int aslFindValidMediaBinding( AsNetworkAddress n, AsMediaAddress m, AsTime t );

// Find the valid binding for media address M at time T
int aslFindValidNetworkBinding( AsNetworkAddress n, AsMediaAddress m, AsTime t );

// Determine if system S is trusted at time T
int aslSystemTrusted( AsSystem s, AsTime t );

//
// Util functions

// Check if the output from GPL is negative
int aslIsGplOutputNegative(char *output);

// Check if the output from GPL is positive
int aslIsGplOutputPositive(char *output);

//
// Unit testing

// Validate logic interface with randomized inputs
int testAsLogicInterfaces( void );

//
// Logic process control

// For the logic program to interact with so we can run the 
int aslForkPrologLogic( void ); 

// write input to the prolog logic process
int aslWritePrologLogic( const char *str ); 

// check if data from the logic program available to read
int aslLogicDataReady( unsigned long dwait );

// read data from the prolog logic process
int aslReadPrologLogic( char *buf, int *len );

// read all of the output from a commoand until prompt
int aslGetPrologOutput( void );

//  wait for outout from the logic
 int aslWaitOutput( char *str, int typ );

// process the signal that the child process as died
void aslChildDeathHandler( int sig );

#endif
