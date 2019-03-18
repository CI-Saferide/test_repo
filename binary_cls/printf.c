#include "classifier.h"

#ifdef CLS_DEBUG

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"

int (*printf_func)() = NULL;

#pragma GCC diagnostic pop

void cls_register_printf(void *func)
{
	printf_func = func;

	cls_dbg("registered printf function\n");
}

#endif
