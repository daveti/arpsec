#ifndef AsLog_INCLUDED
#define AsLog_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsLog.h
//  Description   : The AsLog module implements the logging function for the
//                  arpsec daemon.
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 11:05:23 EDT 2013
//

// Includes
#include <stdarg.h>

//
// Module methods
	
// Set the log filename (STDERR by default)
int setAsLogFilename( const char *fname );

// Log a message to the arpsec deamon log
int asLogMessage( const char *fmt, ... );

// Close the arpsec deamon log
int closeAsLog( void );

// Description	: start the metric timer for outputing to log
void asStartMetricsTimer( void );

// Description	: stop the metrics time and log result
void asStopMetricsTimer( char *label );

// Description	: Compare two timer values (tm2 - tm1)
long asCompareTimes( struct timeval tm1, struct timeval tm2 );

#endif
