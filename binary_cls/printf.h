#ifndef __PRINTF_H__
#define __PRINTF_H__

#ifdef CLS_DEBUG

#include <stdarg.h>

char *get_type_str(unsigned int type);
void cls_register_printf(void *func);
void* get_printf_func(void);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"

#define cls_printf(fmt, ...) ({                         \
       do {                                             \
    	   void (*printf_func)(char *, ...) = get_printf_func(); \
	       if (printf_func)                         \
	       	       printf_func(fmt, ##__VA_ARGS__); \
       } while (0);                                     \
})

#pragma GCC diagnostic pop

#define cls_crit(fmt, ...) \
	cls_printf("[CRIT] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_err(fmt, ...) \
	cls_printf("[ERR] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_warn(fmt, ...) \
	cls_printf("[WARN] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_info(fmt, ...) \
	cls_printf("[INFO] %s: " fmt, __func__, ##__VA_ARGS__)
#define cls_dbg(fmt, ...) \
	cls_printf("[DBG] %s: " fmt, __func__, ##__VA_ARGS__)

#else
#define cls_printf(...)
#define cls_crit(...)
#define cls_err(...)
#define cls_warn(...)
#define cls_info(...)
#define cls_dbg(...)

#endif /* CLS_DEBUG */

#endif /*__PRINTF_H__ */
