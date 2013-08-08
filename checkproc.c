/*
 * Originated by Patrick McDaniel
 * Modified by daveti
 * Jul 7, 2013
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#define GPROLOG_BIN_PATH	"/usr/local/bin/gprolog"

pid_t pid;
int  gprlog_pipefds[2], ret=0, l, gpout_pipefds[2];
char fpath[128], buf[1024];

void aslChildDeathHandler( int sig ) {
    printf( "Child process died! %d]\n", sig );
    return;
}

int aslLogicCommand( char *str ) {

    // Local variables
    char wrBuf[1024];
    int len = -1;

    // Log and send the logic command
    printf( "Sending logic command [%s]", str );
    if ( str[strlen(str)-1] != '\n' ) {

	// Append a CR and send to logic process
	snprintf( wrBuf, 1024, "%s\n", str ); 
	if ( (len = write(gpout_pipefds[1], wrBuf, strlen(wrBuf)+1)) != strlen(wrBuf)+1 ) {
	   fprintf( stderr, "Write failed to child logic [%s]\n", strerror(errno) );
	   exit( -1 );
	}
    } else {

	// Just send the data
	if ( (len = write(gpout_pipefds[1], str, strlen(str)+1)) != strlen(str)+1 ) {
	   fprintf( stderr, "Write failed to child logic [%s]\n", strerror(errno) );
	   exit( -1 );
	}
    }

    // Return the length written
    return( len );
}

int main( int argc, char **argv ) {


    signal( SIGCHLD, aslChildDeathHandler );

    if( (pipe(gprlog_pipefds) == -1) || (pipe(gpout_pipefds) == -1) || ((pid = fork()) == -1) ) {
	printf( "Pipe/fork creation failed for child logic process, aborting [%s]",
	strerror(errno) );
	exit( -1 );
    }

    // If in the child process
    if (pid == 0) {

	// Get the path to the prolog engine, if any
	printf( "Process forked (child live)\n" );
	//sprintf( fpath, "/bin/ls" );
	//sprintf( fpath, "/home/mcdaniel/gprolog-1.4.2/bin/gprolog" );
	sprintf( fpath, GPROLOG_BIN_PATH );

	// Child process 

	// Redirect child output to pipe
	close( gprlog_pipefds[0] );
	if ( (dup2(gprlog_pipefds[1], STDOUT_FILENO) == -1) || 
	    (dup2(gprlog_pipefds[1], STDERR_FILENO) == -1) ) {
	    printf( "dup2 failed for child logic process, aborting [%s]\n", strerror(errno) );
	    exit( -1 );
	}
	close( gprlog_pipefds[1] );

	// Redirect child input from second pipe
	close( gpout_pipefds[1] );
	if ( dup2(gpout_pipefds[0], STDIN_FILENO) == -1) {
	    printf( "dup2 failed for child logic process, aborting [%s]\n", strerror(errno) );
	    exit( -1 );
	}
	close( gpout_pipefds[0] );

	// Now do the exec
	printf( "Child exec logic [%s] ...\n", fpath );
	ret = execl( fpath, fpath, (char *)NULL );
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

    close( gprlog_pipefds[1] );
    close( gpout_pipefds[0] );
    printf( "Process forked (parent live)\n" );

    struct timeval tm;
    tm.tv_sec = 1;
    tm.tv_usec = 0;
    printf( "Waiting ...\n" );
    select(0, NULL, NULL, NULL, &tm);
    printf( "Waiting done.\n" );

    l=read(gprlog_pipefds[0], buf, 1024);
    printf( "Read %d bytes from child [%s]\n", l, buf );
aslLogicCommand( "trust_statement(sys1,X)." );
aslLogicCommand( "halt." );
    printf( "Waiting ...\n" );
    select(0, NULL, NULL, NULL, &tm);
    printf( "Waiting done.\n" );
    l=read(gprlog_pipefds[0], buf, 1024);
    printf( "Read %d bytes from child [%s]\n", l, buf );

    // Return successfully
    return( 0 );
}
