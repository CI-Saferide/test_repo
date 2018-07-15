#ifndef UT_SERVER_ 
#define UT_SERVER_ 

#define UT_DEFAULT_PORT 6789
#define UT_FIXED_MESSAGE_LEN 20
#define UT_CMD_LEARN_STR "LEARN"
#define UT_CMD_PROTECT_STR "PROTECT"
#define UT_CMD_OFF_STR "OFF"
#define UT_CMD_DONE_STR "DONE"

enum UT_CMD_E {
	UT_CMD_INVALID,
	UT_CMD_LERAN,
	UT_CMD_PROTECT,
	UT_CMD_DONE,
	UT_CMD_OFF,
	UT_CMD_MAX,
}; 

int ut_server_start(void);
int ut_server_stop(void);

#endif
