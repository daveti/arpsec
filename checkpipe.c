
int aslForkPrologLogic( void ) {

    // Local variables
    char *path, fpath[128];
    int ret;

    // Setup the signal handler 
    signal( SIGCHLD, aslChildDeathHandler );

    // First create a pipe for process IPC, then fork this process
    printf( "Forking child process for logic ..." );
    if( (pipe(gprlog_pipefds) == -1) || ((aslLogicPid = fork()) == -1) ) {
	asLogMessage( "Pipe/fork creation failed for child logic process, aborting [%s]",
		strerror(errno) );
	exit( -1 );
    }

    // If in the child process
    if (aslLogicPid == 0) {

	// Get the path to the prolog engine, if any
	asLogMessage( "Process forked (child live)" );
	path = getenv( GPROLOG_PATH );
	if ( path == NULL ) {
	    path = GPROLOG_DEFAULT_PATH;
	}
	snprintf( fpath, 128, "%s/%s", path, GPROLOG );

	// Child process 
	if ( (dup2(gprlog_pipefds[0], STDIN_FILENO) == -1) || 
	    (dup2(gprlog_pipefds[1], STDOUT_FILENO) == -1) || 
	    (dup2(gprlog_pipefds[1], STDERR_FILENO) == -1) ) {
	    asLogMessage( "dup2 failed for child logic process, aborting [%s]", strerror(errno) );
	    exit( -1 );
	}
	asLogMessage( "Child exec logic [%s][%s] ...", fpath );
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
