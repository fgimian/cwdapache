// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the MOD_AUTHNZ_CROWD_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// MOD_AUTHNZ_CROWD_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MOD_AUTHNZ_CROWD_EXPORTS
#define MOD_AUTHNZ_CROWD_API __declspec(dllexport)
#else
#define MOD_AUTHNZ_CROWD_API __declspec(dllimport)
#endif

// This class is exported from the mod_authnz_crowd.dll
class MOD_AUTHNZ_CROWD_API Cmod_authnz_crowd {
public:
	Cmod_authnz_crowd(void);
	// TODO: add your methods here.
};

extern MOD_AUTHNZ_CROWD_API int nmod_authnz_crowd;

MOD_AUTHNZ_CROWD_API int fnmod_authnz_crowd(void);
