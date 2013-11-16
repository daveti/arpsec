////////////////////////////////////////////////////////////////////////////////
//
//  File          : arpsecd.c
//  Description   : This the main function for the arpsecd daemon.
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 11:44:08 EDT 2013
//  Dev	    : daveti
//  Modified: Fri Sep 20 10:51:12 PDT 2013
//

// Incliudes	
#include <stdio.h>
#include <unistd.h>
#include <gprolog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

// Project Includes
#include "AsControl.h"
#include "AsLogic.h"
#include "AsLog.h"
#include "AsTMeasure.h"

// Definitions
#define ARPSEC_ARGUMENTS "shfcanl:"
#define USAGE \
    "\nUSAGE: arpsecd [-h] [-l <logfile>] [-s] [-f] [-a] [-c] [-n]\n" \
    "\n" \
    "where:\n" \
    "   -h - display this help information\n" \
    "   -l - set the log file (stderr by default), where\n" \
    "        logfile - the path to the file to place log information.\n" \
    "   -f - force the attestation even if the logic approves the mapping.\n" \
    "   -a - allow the binding if no DB entry found during attestation.\n" \
    "	-c - cache the MAC/IP if the attestation succeed.\n" \
    "	-n - no logic layer invoked (always return 'untrusted' from logic layer).\n" \
    "   -s - simulate the kernel and network traffic\n\n"

//
// Functions

extern pid_t aslLogicPid;
int playwithiface( void ) {
    int status;
    aslForkPrologLogic();

struct timeval tm;
tm.tv_sec = 1;
tm.tv_usec = 0;
asLogMessage( "Waiting ..." );
select(0, NULL, NULL, NULL, &tm);
asLogMessage( "Waiting done." );


    aslGetPrologOutput();
    kill( aslLogicPid, SIGKILL );
    waitpid(aslLogicPid, &status, 0);
    exit( -1 );

}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : This is the main function for the arpsecd deamon
//
// Inputs       : mode - simulate or run normally
// Outputs      : 0 if successful, -1 if not

int main(int argc, char **argv) {

    // Local variables
    int ch;
    int simulate = 0;

    //playwithiface();

    // Process the command line parameters
    while ((ch = getopt(argc, argv, ARPSEC_ARGUMENTS)) != -1) {

	// Look at the parameter
	switch (ch) {
	    case 'h': // Help, print usage
		fprintf( stderr, USAGE );
		return( -1 );

	    case 'l': // Set log filename
		setAsLogFilename( optarg );
		break;

	    case 's': // Simulate flag
		simulate = 1;
		break;

	    case 'f': // Force attest flag
		ascForceAttest();
		break;

	    case 'c': // Enable the cache
		ascEnableCache();
		break;

	    case 'n': // Disable the logic layer
		aslDisableLogic();
		break;

	    case 'a': // Allow the binding if no DB entry found
		astAllowBinding();
		break;

	    default:  // Default (unknown)
		fprintf( stderr, "Unknown command line oition (%c), aborting.", ch );
		return( -1 );
	}
    }

    // Go into the arpsec control loop and process
    ascControlLoop( simulate );

    // Return successfully
    return( 0 );
}
