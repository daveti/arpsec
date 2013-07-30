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

// Project Includes
#include <stdio.h>
#include "AsDefs.h"

//
// Module methods
	
// Attest that the system is in a good state.
int astAttestSystem( AsSystem s );
	
#endif
