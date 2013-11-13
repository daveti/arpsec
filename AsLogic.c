////////////////////////////////////////////////////////////////////////////////
//
//  File	  : AsLogic.cpp
//  Description   : The AsLogic module implements a shim for the logic
//		    program for the arpsec daemnon.
//
//  Author  : Patrick McDaniel
//  Created : Sun Mar 24 07:21:50 EDT 2013
//
//  Modified: Jul 7, 2013
//  By	    : daveti
//
//

// Includes
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <regex.h>

// Project Includes
#include "AsLogic.h"
#include "AsLog.h"

// Defines
#define GPROLOG "gprolog"
#define GPROLOG_PATH "GRPROLOG_PATH"
#define GPROLOG_PROGRAM "arpsec.pl"
//daveti
#define GPROLOG_DEFAULT_PATH "/usr/local/gprolog-1.4.2/bin"
//#define GPROLOG_DEFAULT_PATH "/usr/bin"
#define VALID_BINDING_MARKER "X = "
#define MAX_OUTPUT_LINES 25
#define MAX_OUTPUT_LINE_LENGTH 256
#define ASL_WAIT_CONTAINS   1 // String is somewhere in output
#define ASL_WAIT_STARTSWITH 2 // Output starts with string
#define ASL_WAIT_IS	    3 // Output is string

//
// Module local data
int	aslogic_initialized = 0;    // Flag indicating that the library has been initialized
int	gprlog_opipe[2];	    // The pipe handles to the prolog engine (output to pl)
int	gprlog_ipipe[2];	    // The pipe handles to the prolog engine (input to pl)
pid_t	aslLogicPid;
int	aslNumOutputLines;	    // The number of output lines
char	aslOutputLines[MAX_OUTPUT_LINES][MAX_OUTPUT_LINE_LENGTH];  // logic buffer (input)
char	aslOutputBuffer[MAX_OUTPUT_LINES*MAX_OUTPUT_LINE_LENGTH];  // logic buffer (lines)

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslInitLogic
// Description	: Initialize the interface to the Logic engine (with parameters)
//
// Inputs	: argc - the number of parameters
//		  argv - points to the parameters
// Outputs	: 0 if successful, -1 if not

int aslInitLogic( void ) {

    // Check if already initialized
    if ( aslogic_initialized ) return( 0 );
	
    // Initialize and set internal values
    // NOTE: gprolog needs ration argc/argv or it crashes, so I am faking it
    asLogMessage( "Intializing arpsecd logic ..." );
    aslForkPrologLogic();
    if ( ! aslWaitOutput( "bytes written", ASL_WAIT_CONTAINS ) ) {
	asLogMessage( "Prolog launch failed, aborting." );
	exit( -1 );
    };
    aslogic_initialized = 1;
    asLogMessage( "arpsecd logic initialized." );
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslShutdownLogic
// Description	: Initialize the interface to the Logic engine (with parameters)
//
// Inputs	: argc - the number of parameters
//		  argv - points to the parameters
// Outputs	: 0 if successful, -1 if not

// Shutdown the PL interface
int aslShutdownLogic( void ) {

	// Check if not initialized, close interface
	if ( ! aslogic_initialized ) return( 0 );
	asLogMessage( "Stopping arpsecd logic ..." );
    aslWritePrologLogic( "halt.\n" );
	asLogMessage( "Done." );
	aslogic_initialized = 0;
	return( 0 );
}

//
// Assertion of trust statements

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslAddTrustStatement
// Description	: Add a trust statement to the logic
//
// Inputs	: s - system that was trusted
//		  t - time at which the trust statement was made
// Outputs	: 0 if successful, -1 if not

int aslAddTrustStatement( AsSystem s, AsTime t ) {

    // Local variables
    char cmd[256];

    // Start processing, if needed 
    if ( ! aslogic_initialized ) aslInitLogic();

    // Setup command and run 
    snprintf( cmd, 256, "asserta(trust_statement(%s,%lu)).\n", s, t );
    aslWritePrologLogic( cmd );

    // Get output and process
    if ( ! aslWaitOutput( "yes", ASL_WAIT_IS ) ) {
	asLogMessage( "Prolog launch failed, aborting." );
	exit( -1 );
    }
    asLogMessage( "Trust statement added successfully (%s,%lu)", s, t );

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: AddBindingStatement
// Description	: Add a binding statement to the logic
//
// Inputs	: s - system that makes the binding assertion
//		  m - the media address
//		  n - the network address
//		  t - time at which the statement was made
// Outputs	: 0 if successful, -1 if not

int aslAddBindingStatement( AsSystem s, AsMediaAddress m, AsNetworkAddress n, AsTime t ) {

    // Local variables
    char cmd[256];

    // Start processing, if needed 
    if ( ! aslogic_initialized ) aslInitLogic();

    // Setup command and run 
    snprintf( cmd, 256, "asserta(binding_statement(%s,%s,%s,%lu)).\n", s, n, m, t );
    aslWritePrologLogic( cmd );

    // Get output and process
    if ( ! aslWaitOutput( "yes", ASL_WAIT_IS ) ) {
	asLogMessage( "Prolog launch failed, aborting." );
	exit( -1 );
    }
    asLogMessage( "Binding statement added successfully (%s,%lu)", s, t );

    // Return successfully
    return( 0 );
}
	
//
// Logic query methods

////////////////////////////////////////////////////////////////////////////////
//
// Function	: FindValidMediaBinding
// Description	: Find the valid binding for network address N at time T
//
// Inputs	: n - the network address to find binding fore
//		  m - the media address structure to copy into 
//		  t - time at which the binding should be true
// Outputs	: 1 if found, 0 if not
	
int aslFindValidMediaBinding( AsNetworkAddress n, AsMediaAddress m, AsTime t ) {

    // Local variables
    int i;
    char cmd[256], *buf;

    // Start processing, if needed 
    if ( ! aslogic_initialized ) aslInitLogic();

    // Setup command and run 
    snprintf( cmd, 256, "valid_binding(%s,X,%lu).\n", n, t );
    aslWritePrologLogic( cmd );

    // Get output and process
    if ( ! aslWaitOutput( "X", ASL_WAIT_STARTSWITH ) ) {
	asLogMessage( "Wait valid media binding result failed" );
	exit( -1 );
    }

    // Parse out the answer
    for ( i=0; i<aslNumOutputLines; i++)  {

	// Is this the line we are looking for?
	if ( strncmp( VALID_BINDING_MARKER, aslOutputLines[i], strlen(VALID_BINDING_MARKER)) == 0 ) {

	    // Copy and remove trailing space
	    strncpy( m, &aslOutputLines[i][strlen(VALID_BINDING_MARKER)], MAX_MEDADDR_LENGTH );
	    buf = strchr( m, ' ' );
	    if ( buf != NULL ) *buf = 0x0;
	    asLogMessage( "Find valid media binding successfully (%s,%lu)->[%s]", n, t, m );

	    // If prolog is waiting for more input
	    if (  strchr(aslOutputLines[i], '?') != NULL ) {

		// Send return and wait for response
		aslWritePrologLogic( "\n" );
		if ( ! aslWaitOutput( "yes", ASL_WAIT_IS ) ) {
		    asLogMessage( "Prolog launch failed, aborting." );
		    exit( -1 );
		}
	    }

	    // Return we found it
	    return( 1 );
	}
    }

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: FindValidNetworkBinding
// Description	: Find the valid binding for network address N at time T
//
// Inputs	: n - the network address structure to place the value in
//		  m - the network address to find binding fore
//		  t - time at which the binding should be true
// Outputs	: 1 if found, 0 if not

int aslFindValidNetworkBinding( AsNetworkAddress n, AsMediaAddress m, AsTime t )  {

    // Local variables
    int i;
    char cmd[256], *buf;

    // Start processing, if needed 
    if ( ! aslogic_initialized ) aslInitLogic();

    // Setup command and run 
    snprintf( cmd, 256, "valid_binding(X,%s,%lu).\n", m, t );
    aslWritePrologLogic( cmd );

    // Get output and process
    if ( ! aslWaitOutput( "X", ASL_WAIT_STARTSWITH ) ) {
	asLogMessage( "Wait valid network binding result failed" );
	exit( -1 );
    }

    // Parse out the answer
    for ( i=0; i<aslNumOutputLines; i++)  {

	// Is this the line we are waiting for?
	if ( strncmp( VALID_BINDING_MARKER, aslOutputLines[i], strlen(VALID_BINDING_MARKER)) == 0 ) {

	    // Copy and remove trailing space
	    strncpy( n, &aslOutputLines[i][strlen(VALID_BINDING_MARKER)], MAX_MEDADDR_LENGTH );
	    buf = strchr( n, ' ' );
	    if ( buf != NULL ) *buf = 0x0;
	    asLogMessage( "Find valid network binding successfully (%s,%lu)->[%s]", m, t, n );

	    // If prolog is waiting for more input
	    if (  strchr(aslOutputLines[i], '?') != NULL ) {

		// Send return and wait for response
		aslWritePrologLogic( "\n" );
		if ( ! aslWaitOutput( "yes", ASL_WAIT_IS ) ) {
		    asLogMessage( "Prolog launch failed, aborting." );
		    exit( -1 );
		}
	    }

	    // Return we found it
	    return( 1 );
	}
    }

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslSystemTrusted
// Description	: Determine if system S is trusted at time T
//
// Inputs	: s - system to be trusted
//		  t - time at which the system is trusted
// Outputs	: 1 if trusted, 0 if not

int aslSystemTrusted( AsSystem s, AsTime t ) {

    // Local variables
    int i;
    char cmd[256];

    // Start processing, if needed 
    if ( ! aslogic_initialized ) aslInitLogic();

    // Setup command and run 
//daveti: timing for logic running
struct timeval tpstart,tpend;
float timeuse = 0;
gettimeofday(&tpstart,NULL);

    snprintf( cmd, 256, "trusted(%s,%lu).\n", s, t );
    aslWritePrologLogic( cmd );

    // Get the input
    int lines = aslGetPrologOutput();

//daveti: timing end
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
asLogMessage("Total time on Prolog_Logic_Run() is [%f] ms", timeuse);

    for ( i=0; i<lines; i++)  {

	// daveti: handle speical case with empty ouput
	if (aslOutputLines[i][0] == 0x0)
		continue;

	// Positive confirmation
	if ( strcmp( aslOutputLines[i], "yes") == 0 ) {
	    asLogMessage( "System (%s) found to be trusted at time (%lu)", s, t );
	    return( 1 );
	}

	// positive confirmation version 2
	if ( strncmp( aslOutputLines[i], "true", 4) == 0 ) {
	    asLogMessage( "System (%s) found to be trusted at time (%lu)", s, t );
	    return( 1 );

	    // If prolog is waiting for more input
	    if (  strchr(aslOutputLines[i], '?') != NULL ) {

		// Send return and wait for response
		aslWritePrologLogic( "\n" );
		if ( ! aslWaitOutput( "yes", ASL_WAIT_IS ) ) {
		    asLogMessage( "Prolog launch failed, aborting." );
		    //exit( -1 );
		    //daveti: make it untrusted!
		    return( 0 );
		}
	    }

	}

	// Positive confirmation final version
	// All other patterns of positive cases
	// should be added into aslIsGplOutputPositive()
	// Aug 23, 2013
	// daveti
	if (aslIsGplOutputPositive(aslOutputLines[i]) == 1)
	{
		asLogMessage("System (%s) found to be trusted at time (%lu) with time delay", s, t);
		return( 1 );
	}

	// Negative confirmation
	if ( strcmp( aslOutputLines[i], "no") == 0 ) {
	    asLogMessage( "System (%s) found to be NOT trusted at time (%lu)", s, t );
	    return( 0 );
	}

	// daveti: add another pattern of negative confirmation
	// currently no idea why this may be triggered...
	if ( aslIsGplOutputNegative(aslOutputLines[i]) == 1 ) {
	    asLogMessage( "System (%s) found to be NOT trusted at time (%lu) with time delay", s, t);
	    return ( 0 );
	}
    }

    // Did not get a response we could recognize, abort
    asLogMessage( "Faild to get a postive or negative result on system trust (%s,%lu)", s, t);
    //exit( -1 );
    //daveti: make it untrusted
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: testAsLogicInterface
// Description	: Validate logic interface with randomized inputs
//
// Inputs	: none
// Outputs	: 0 if successful, -1 if not

int testAsLogicInterfaces( void ) {

    // Set randomized information
    int rnd = as_random(100), rnd2 = as_random(100);
    char sys[32], media[MAX_MEDADDR_LENGTH], network[MAX_NETADDR_LENGTH];
    sprintf( sys, "sys%03d", rnd );
    AsNetworkAddress n = network;
    AsMediaAddress m = media;

    // Now call the logic functions
    asLogMessage( "Unit testing the arpsec logic with randomized data." );
    asLogMessage( "Adding test trust statment for system [%s], time [%d].", sys, rnd2 );
    aslAddTrustStatement( sys, rnd2 );
    aslSystemTrusted( sys, rnd2 );
    aslAddBindingStatement( sys, "mediaA", "netB", rnd2 ); 
    aslFindValidMediaBinding( "netB", m, rnd2+1 );
    aslFindValidNetworkBinding( n, "mediaA", rnd2+1 );
    asLogMessage( "Unit testing complete." );

    // Return sucessfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslForkPrologLogic
// Description	: For the logic program to interact with so we can run the 
//		  logic in a child process.
//
// Inputs	: none
// Outputs	: 0 if successful, -1 if not

int aslForkPrologLogic( void ) {

    // Local variables
    char *path, fpath[128];
    int ret;

    // Setup the signal handler 
    signal( SIGCHLD, aslChildDeathHandler );

    // First create a pipe for process IPC, then fork this process
    asLogMessage( "Forking child process for logic ..." );
    if( (pipe(gprlog_opipe) == -1) || (pipe(gprlog_ipipe) == -1) ||
	    ((aslLogicPid = fork()) == -1) ) {
	asLogMessage( "Pipe/fork creation failed for child logic process, aborting [%s]",
		strerror(errno) );
	exit( -1 );
    }

    // If in the child process
    if (aslLogicPid == 0) {

	// Redirect output of child process to input of parent
	close( gprlog_opipe[0] );
	if ( (dup2(gprlog_opipe[1], STDOUT_FILENO) == -1) || 
	    (dup2(gprlog_opipe[1], STDERR_FILENO) == -1) ) {
	    asLogMessage( "dup2 failed for child logic process, aborting [%s]", strerror(errno) );
	    exit( -1 );
	}
	close( gprlog_opipe[1] );

	// Redirect child input from second pipe
	close( gprlog_ipipe[1] );
	if ( dup2(gprlog_ipipe[0], STDIN_FILENO) == -1 ) {
	    asLogMessage( "dup2 failed for child logic process, aborting [%s]\n", strerror(errno) );
	    exit( -1 );
	}
	close( gprlog_ipipe[0] );

	// Get the path to the prolog engine, if any
	asLogMessage( "Process forked (child live)" );
	path = getenv( GPROLOG_PATH );
	if ( path == NULL ) {
	    path = GPROLOG_DEFAULT_PATH;
	}
	snprintf( fpath, 128, "%s/%s", path, GPROLOG );

	asLogMessage( "Child exec logic [%s][--consult-file[%s] ...", fpath, GPROLOG_PROGRAM );
	ret = execl( fpath, fpath, "--consult-file", GPROLOG_PROGRAM, (char *)NULL );
	//ret = execl( "/usr/bin/tail", "/usr/bin/tail", "-f", "x", (char *)NULL );
	// Nothing below this line should be executed by child process. If so, 
	// it means that the execl function wasn't successfull, so lets exit:
	if ( ret == -1 ) {
	    fprintf( stderr, "Child logic engine exec failed [%s]\n", strerror(errno) );
	} else {
	    fprintf( stderr, "Child logic process exited.\n" );
	}
	exit(1);
    }

    // Parent side, close the pipes we won't use
    close( gprlog_opipe[1] );
    close( gprlog_ipipe[0] );
    asLogMessage( "Process forked (parent live)" );

    // In parent, return
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslWritePrologLogic
// Description	: write input to the prolog logic process
//
// Inputs	: str - the string to read
// Outputs	: 0 if successful, -1 if not

int aslWritePrologLogic( const char *str ) {

    // Local variables
    struct timeval tm;
    fd_set wrfds;

    // Set the FD set (wait for write select to pop)
    FD_ZERO( &wrfds );
    FD_SET( gprlog_ipipe[1], &wrfds );
    tm.tv_sec = 0;
    tm.tv_usec = 1000000L; // 1 sec
    if ( select(gprlog_ipipe[1]+1, NULL, &wrfds, NULL, &tm) <= 0 ) {
	asLogMessage( "Failed waiting for write select.\n" );
	exit( -1 );
    }

    // Write the bytes to the external process
    asLogMessage( "Writing to logic [%s]", str );
    if ( write(gprlog_ipipe[1], str, strlen(str)+1) == strlen(str)+1 ) {
	return( 0 );
    }

    // Fail out
    asLogMessage( "Failued to write string, aborting, string=%s", str );
    exit( -1 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslLogicDataReady
// Description	: check if data from the logic program available to read
//
// Inputs	: dwait - wait time in usec
// Outputs	: 1 if data available, 0 if not

int aslLogicDataReady( unsigned long dwait ) {

    // Local variables
    struct timeval tm;
    fd_set rdfds;
    int ret;

    // Set the FD set
    FD_ZERO( &rdfds );
    FD_SET( gprlog_opipe[0], &rdfds );
    tm.tv_sec = dwait/1000000L;
    tm.tv_usec = dwait%1000000L;

    // Now select the file descriptor
    ret = select(gprlog_opipe[0]+1, &rdfds, NULL, NULL, &tm);
    return( ret > 0 );

}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslReadPrologLogic
// Description	: read data from the prolog logic process
//
// Inputs	: buf - data to write
//		  len - length of data to write
// Outputs	: number of bytes read

int aslReadPrologLogic( char *buf, int *len ) {

    // Read the bytes to the external process
    int l = 0;
    asLogMessage( "Data %s ready for reading from logic.", (aslLogicDataReady(100000L)) ? "is" : "is not" );
    if ( (l=read(gprlog_opipe[0], buf, *len)) >= 0 ) {
	buf[l] = 0x0;
	//asLogMessage( "Read %d bytes from pipe [%s]", l, (l < 1) ? "(empty)" : buf );
	*len = l;
	return( l );
    }

    // Fail out
    if ( l == -1 ) {
	asLogMessage( "Failued to read data from logic, aborting, errror=%s", 
		strerror(errno) );
    } else {
	asLogMessage( "Failued to read data from logic, aborting, ret=%d", l );
    }
    exit( -1 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslGetPrologOutput
// Description	: read all of the output from a commoand until prompt
//
// Inputs	: void
// Outputs	: 0 if successful, -1 if not

int aslGetPrologOutput( void ) {

    // Local variables
    char *ptr;
    int pos = 0, len, tpos;

    // While more data to read
    do {
	if (  aslLogicDataReady(100000L) ) {
	    len = (MAX_OUTPUT_LINES*MAX_OUTPUT_LINE_LENGTH) - pos;
	    pos += aslReadPrologLogic( &aslOutputBuffer[pos], &len );
	} else {
	    len = 0;
	}
    } while ( len > 0 );

    // If no data read, just return
    if ( pos == 0 ) {
	aslNumOutputLines = 0;
	return( aslNumOutputLines );
    }

    // Parse out the output into lines
    tpos = 0;
    aslNumOutputLines = 0;
    do {

	// Parse out the next line of output
	ptr = strchr( &aslOutputBuffer[tpos], '\n' );
	if ( ptr == NULL ) {
	    len = strlen( &aslOutputBuffer[tpos] );
	} else {
	    len =  (int)(ptr-&aslOutputBuffer[tpos]);
	} 
	strncpy( aslOutputLines[aslNumOutputLines],  &aslOutputBuffer[tpos], len );
	aslOutputLines[aslNumOutputLines][len] = 0x0; // Null terminate
	asLogMessage( "GPL output [%s]", aslOutputLines[aslNumOutputLines] );
	tpos += len + 1;
	aslNumOutputLines ++;

    } while ( tpos<pos );

    // Return the number of lines read
    return( aslNumOutputLines );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslWaitOutput
// Description	: wait for outout from the logic
//
// Inputs	: str - string to look for
//		  typ - contains
// Outputs	: 1 if found in output, 0  otherwise

int aslWaitOutput( char *str, int typ ) {

    // Local variables
    int i, found;

    // Get the output, process the lines
    asLogMessage( "Waiting for input [%s], ty=%d", str, typ );
    int lines = aslGetPrologOutput();
    for ( i=0; i<lines; i++ ) {

	// depends on what we are waiting for
	switch (typ) {

	    case ASL_WAIT_CONTAINS : // String is somewhere in output
		found = (strstr( aslOutputLines[i], str ) != NULL);
		break;

	    case ASL_WAIT_STARTSWITH : // Output starts with string
		found = strncmp( aslOutputLines[i], str, strlen(str) );
		break;

	    case ASL_WAIT_IS : // Output is string
		found = strcmp( aslOutputLines[i], str );
		break;

	    default: // Illegal
		asLogMessage( "Illegal wait type in aslogic, aborting [%d]", typ );
		exit( -1 );
	}

	// If found then return that fact
	if ( found ) {
	    return( 1 );
	}

    }

    // Return not found
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: aslChildDeathHandler
// Description	: process the signal that the child process as died
//
// Inputs	: the signal (should be SIGCHLD)
// Outputs	: none

void aslChildDeathHandler( int sig ) {
    asLogMessage( "Child process died! %d", sig );
    return;
}

#if 0
    // The code below will be executed only by parent. You can write and read
    // from the child using pipefd descriptors, and you can send signals to 
    // the process using its pid by kill() function. If the child process will
    // exit unexpectedly, the parent process will obtain SIGCHLD signal that
    // can be handled (e.g. you can respawn the child process).

    // Now, you can write to the process using pipefd[0], and read from pipefd[1]:

char buf[256];
    write(pipefd[0], "message", strlen("message")); // write message to the process
    read(pipefd[1], buf, sizeof(buf)); // read from the process. Note that this will catch 
				       // standard  output together with error output
    kill(pid, signo); //send signo signal to the child process

#endif

////////////////////////////////////////////////////////////////////////////////
//
// Function     : aslIsGplOutputNegative
// Description  : check if the output from GPL is negative
//
// Inputs       : output - GPL output
// Outputs      : 0 if False, 1 if True, -1 if internal error
// Dev		: daveti

int aslIsGplOutputNegative(char *output)
{
	// There may be different patterns of negative response from GPL
	// we need to handle. This function is used to include all these
	// stupid things...as I am not familiar with GPL:(
	// BTW, POSIX regex is used here - hopefully it will not cause
	// trouble for portability....(who cares:)

	int rtn = 0;
	regex_t regex;
	char msgBuf[100] = {0};

	// Pattern 1: [(X ms) no], e.g., [(4 ms) no]
	rtn = regcomp(&regex, "\\([0-9]+ ms\\) no", REG_EXTENDED);
	if (rtn)
	{
		asLogMessage("aslIsGplOutputNegative: Error on regcomp [%s]", strerror(errno));
		return -1;
	}

	rtn = regexec(&regex, output, 0, NULL, 0);
	if (!rtn)
	{
		asLogMessage("aslIsGplOutputNegative: Info - [%s] matches pattern 1", output);
		// To support multiple patterns in futher
		// return inmmediately if matches
		// otherwise keep hunting
		return 1;
	}
	else if (rtn == REG_NOMATCH)
		asLogMessage("aslIsGplOutputNegative: Info - [%s] does not match pattern 1", output);
	else
	{
		regerror(rtn, &regex, msgBuf, sizeof(msgBuf));
		asLogMessage("aslIsGplOutputNegative: Info - [%s] match failed for pattern 1 [%s]", output, msgBuf);
	}

	regfree(&regex);

	// Pattern 2: ...

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : aslIsGplOutputPositive
// Description  : check if the output from GPL is positive
//
// Inputs       : output - GPL output
// Outputs      : 0 if False, 1 if True, -1 if internal error
// Dev          : daveti

int aslIsGplOutputPositive(char *output)
{
        // There may be different patterns of positive response from GPL
        // we need to handle. This function is used to include all these
        // stupid things...as I am not familiar with GPL:(
        // BTW, POSIX regex is used here - hopefully it will not cause
        // trouble for portability....(who cares:)

        int rtn = 0;
        regex_t regex;
        char msgBuf[100] = {0};

        // Pattern 1: [(X ms) yes], e.g., [(4 ms) yes]
        rtn = regcomp(&regex, "\\([0-9]+ ms\\) yes", REG_EXTENDED);
        if (rtn)
        {
                asLogMessage("aslIsGplOutputPositive: Error on regcomp [%s]", strerror(errno));
                return -1;
        }

        rtn = regexec(&regex, output, 0, NULL, 0);
        if (!rtn)
        {
                asLogMessage("aslIsGplOutputPositive: Info - [%s] matches pattern 1", output);
                // To support multiple patterns in futher
                // return inmmediately if matches
                // otherwise keep hunting
                return 1;
        }
        else if (rtn == REG_NOMATCH)
                asLogMessage("aslIsGplOutputPositive: Info - [%s] does not match pattern 1", output);
        else
        {
                regerror(rtn, &regex, msgBuf, sizeof(msgBuf));
                asLogMessage("aslIsGplOutputPositive: Info - [%s] match failed for pattern 1 [%s]", output, msgBuf);
        }

        regfree(&regex);

        // Pattern 2: ...

        return 0;
}

