#include <stdio.h>
#include <gprolog.h>
#include "ArpsecLogicInterface.h"

int main(int argc, char **argv) {
	printf( "Hello world!\n" ); 
	
	ArpsecLogicInterface alogic;
	alogic.initialize();
	alogic.shutdown();
	
	// Return successfully
	return( 0 );
}