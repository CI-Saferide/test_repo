#ifndef  __SAL_FILTER__
#define  __SAL_FILTER__

#include "sr_sal_common.h"

SR_32 sal_filter_path_init(void);
SR_32 sal_filter_path_add(char *path);
SR_32 sal_filter_path_del(char *path);
SR_BOOL sal_filter_path_is_match(char *path);
SR_32 sal_filter_path_print(void);
void sal_filter_path_deinit(void);

#endif
