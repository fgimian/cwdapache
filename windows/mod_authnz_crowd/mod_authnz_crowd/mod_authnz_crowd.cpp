// mod_authnz_crowd.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "mod_authnz_crowd.h"


// This is an example of an exported variable
MOD_AUTHNZ_CROWD_API int nmod_authnz_crowd=0;

// This is an example of an exported function.
MOD_AUTHNZ_CROWD_API int fnmod_authnz_crowd(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see mod_authnz_crowd.h for the class definition
Cmod_authnz_crowd::Cmod_authnz_crowd()
{
	return;
}
