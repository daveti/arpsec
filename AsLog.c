////////////////////////////////////////////////////////////////////////////////
//
//  File	  : AsLog.cpp
//  Description   : The AsLog module implements the logging function for the
//		    arpsec daemon.
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 11:05:23 EDT 2013

//
// Includes
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>

// Project Includes
#include "AsLog.h"

// Defines
#define MAX_LOG_MESSAGE_SIZE 256

//
// Local data
char *	aslog_filename	= NULL;	    // The filename of the log
int	aslog_fhandle	= -1;	    // The file handle of the log

//
// Module functions

////////////////////////////////////////////////////////////////////////////////
//
// Function	: asLogMessage
// Description	: Log a message to the arpsec deamon log
//
// Inputs	: fmt - the log data format
//		  ... - the arguments themselves
// Outputs	: 0 if successfull, -1 if failure

int asLogMessage( const char *fmt, ... ) {

    // Local variables
    char msg[MAX_LOG_MESSAGE_SIZE], msg2[MAX_LOG_MESSAGE_SIZE], tmstr[MAX_LOG_MESSAGE_SIZE];
    int ret, fh;
    time_t tm;
    va_list args;

    // If we have a filename and need to open
    if ( (aslog_filename != NULL) && (aslog_fhandle == -1) ) {

	// Open the log for writing (append if existing)
	if ( (aslog_fhandle = open(aslog_filename, O_APPEND|O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR)) == -1 ) {
	    fprintf( stderr, "Fatal error unable to open arpsec log [%s], error [%s]\n",
		    aslog_filename, strerror(errno) );
	}

    }

    // Get correctly terminated timestamp
    time(&tm);
    snprintf( tmstr,  MAX_LOG_MESSAGE_SIZE, "%s", ctime((const time_t *)&tm) );
    tmstr[strlen(tmstr)-1] = 0x0;

    // Setup the "printf" like message
    va_start( args, fmt );  
    vsnprintf( msg, MAX_LOG_MESSAGE_SIZE, fmt, args );
    va_end( args );  
    if ( msg[strlen(msg)-1] == '\n' ) msg[strlen(msg)-1] = 0x0; // Strip tailing CR if needed
    snprintf( msg2, MAX_LOG_MESSAGE_SIZE, "%s : %s\n", tmstr, msg );

    // Write the entry to the log and return
    fh = (aslog_fhandle == -1) ? 1 : aslog_fhandle;
    if ( (ret=write(fh, msg2, strlen(msg2)) != (int)strlen(msg2)) ) {
	fprintf( stderr, "Fatal error unable to write to arpsec log [%s], text [%s] error [%s]\n",
		    aslog_filename, msg2, strerror(errno) );
	exit( -1 );
    }

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: setAsLogFilename
// Description	: set the filename of the log
//
// Inputs	: fname - full path to log file
// Outputs	: none

int setAsLogFilename( const char *fname ) {

    // Discard old filename if needed
    if ( aslog_filename != NULL ) {
	free( aslog_filename );
	aslog_filename = NULL;
    }

    // Duplicate the string and return
    aslog_filename = strdup( fname );
    return( 1 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: closeAsLog
// Description	: Close the arpsec deamon log
//
// Inputs	: s - system to attest
// Outputs	: 0 if successful, -1 if not

int closeAsLog( void ) {

    // Cleanup filename
    if ( aslog_filename != NULL ) {
	free( aslog_filename );
	aslog_filename = NULL;
    }

    // Close and return succesfully
    close( aslog_fhandle );
    aslog_fhandle = -1;
    return( 0 );
}


struct timeval asMetricTimer;

////////////////////////////////////////////////////////////////////////////////
//
// Function	: startMetricsTimer
// Description	: start the metric timer for outputing to log
//
// Inputs	: none
// Outputs	: 0 if successful, -1 if not

void asStartMetricsTimer( void ) {
    gettimeofday( &asMetricTimer, NULL );
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: asStopMetricsTimer
// Description	: stop the metrics time and log result
//
// Inputs	: label - label to place on log
// Outputs	: 0 if successful, -1 if not

void asStopMetricsTimer( char *label ) {
    struct timeval now;
    long tm; 

    // Get the time and log it
    gettimeofday( &now, NULL );
    tm = asCompareTimes( asMetricTimer, now );
    asLogMessage( "METRIC: %s : %lu", label, tm );
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: asStopMetricsTimer
// Description	: Compare two timer values (tm2 - tm1)
//
// Inputs	: tm1 - first timer
//                tm2 - second timer
// Outputs	: 0 if successful, -1 if not

long asCompareTimes( struct timeval tm1, struct timeval tm2 ) {
    long retval = 0;
    if ( tm2.tv_usec < tm1.tv_usec ) {
	retval = (tm2.tv_sec-tm1.tv_sec-1)*1000000L;
	retval += ((tm2.tv_usec+1000000L)-tm1.tv_usec);
    } else {
	retval = (tm2.tv_sec-tm1.tv_sec)*1000000L;
	retval += (tm2.tv_usec-tm1.tv_usec);
    }
    return( retval );
}
