#ifndef AsTMeasure_INCLUDED
#define AsTMeasure_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsTMeasure.h
//  Description   : The AsTMeasure module implements a shim for the system 
//		    trust validation for the arpsec daemnon.
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 09:33:11 EDT 2013
//
//  Change  : First implementation
//  Dev	    : Dave Tian
//  Modified: Thu Sep 19 16:48:27 PDT 2013
//

// Project Includes

#include "AsTpmDB.h"

#define AST_REMOTE_TPMD_PORT_STRING		"30004"
#define AST_SOCK_BUFF_SIZE			8192
#define AST_SOCK_RECV_TIMEOUT			2	// second

//
// Module methods

// Init the Attest subsystem
int astInitAttest(int mode);
	
// Attest that the system is in a good state.
int astAttestSystem(askRelayMessage *msg);

// Find the DB entry based on the msg recv'd
tpmdb_entry *astFindDBEntry(askRelayMessage *msg);

// Allow the binding if no DB entry found during attestation
void astAllowBinding(void);
	
#endif
