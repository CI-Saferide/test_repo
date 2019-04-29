#include "classifier.h"

#ifdef CLS_DEBUG

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"

static int (*printf_func)(char *fmt, ...) = NULL;

#pragma GCC diagnostic pop

void* get_printf_func(void)
{
	return printf_func;
}

void cls_register_printf(void *func)
{
	printf_func = func;

	cls_dbg("registered printf function\n");
}

char *get_type_str(unsigned int type)
{
	switch (type) {
	case CLS_IP_RULE_TYPE:
		return "ip";
	case CLS_CAN_RULE_TYPE:
		return "can";
	case CLS_FILE_RULE_TYPE:
		return "file";
	default:
		return "n\a";
	}
}

#endif /* CLS_DEBUG */
