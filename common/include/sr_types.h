#ifndef __SR_TYPES__
#define __SR_TYPES__

/* basic variables definitions */
#define SR_U8 		unsigned char
#define SR_U16 		unsigned short
#define SR_U32 		unsigned int
#define SR_U64 		unsigned long long
#define SR_8 		char
#define SR_16 		short
#define SR_32 		int
#define SR_64 		long long
#define SR_BOOL 	SR_U8
#define SR_TRUE		(SR_BOOL)1
#define SR_FALSE 	(SR_BOOL)0
#define SR_SUCCESS 	0
#define SR_NOT_FOUND	1	
#define SR_ERROR 	-1
#define SR_MAX_PATH 1024
#define SR_DIR_SRC (SR_U8)0
#define SR_DIR_DST (SR_U8)1

#define MAX(X, Y) ((X) >= (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) <= (Y) ? (X) : (Y))

#endif /*__SR_TYPES__ */
