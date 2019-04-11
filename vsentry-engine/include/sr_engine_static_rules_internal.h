#ifndef __STATIC_RULES_INTERNAL_H
#define __STATIC_RULES_INTERNAL_H

#include "file_rule.h"

typedef struct {
	SR_U32  rule_id;
	char	filename[FILE_NAME_SIZE];
	char	permission[4];
	char	user[USER_NAME_SIZE];
	char	program[PROG_NAME_SIZE]; 
} static_file_rule_t;

#ifdef PRODUCTION_MODE
static static_file_rule_t static_wl [] = {
/*   Rule_id   File path                                          permission user     program}, */
	{0,        "/lib/modules/4.9.88+gaf87a92/extras/kgkp.ko",     "r",       "root",  "/oldroot/usr/bin/init"},
	{0,        "/qa/malice.ko",                                   "r",       "root",  "/oldroot/usr/bin/init"},
	{0,        "/lib/module/YAS",                                 "r",       "root",  "/oldroot/usr/bin/init"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/cmb_drvc"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/cmb_main"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/dpa"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/init"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/ivs"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/sswa_agent"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/telemetry"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/ugkp"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/unionfs"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/vproxy"},
	{2,        "/oldroot/pivot/underlay",                         "r",       "root",  "/oldroot/usr/bin/unionfs"},
	{2, ""},  // Must be the last entry.
};
#else
static static_file_rule_t static_wl [] = {
/*   Rule_id   File path                                          permission user     program}, */
	{0,        "/lib/modules/4.9.88-imx_4.9.88_imx8qxp_beta2+g05f46d3/extra/kgkp.ko",     "r",       "root",  "/oldroot/usr/bin/init"},
	{0,        "/qa/malice.ko",                                   "r",       "root",  "/oldroot/usr/bin/init"},
	{0,        "/lib/modules/yas",                                 "r",       "root",  "/oldroot/usr/bin/init"},
	{0,        "/etc/yas/kgkpdev",                                "r",       "root",  "/oldroot/usr/bin/init"},
	{0,        "/lib/modules/4.9.88-imx_4.9.88_imx8qxp_beta2+g05f46d3/extra/kgkp_dev.ko", "r",       "root",  "/oldroot/usr/bin/init"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/cmb_drvc"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/cmb_main"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/dpa"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/init"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/ivs"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/sswa_agent"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/telemetry"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/ugkp"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/unionfs"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/vproxy"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/qa_client"},
	{1,        "/customer_persistent/YAS",                        "rw",      "root",  "/oldroot/usr/bin/qa_server"},
	{2,        "/oldroot/pivot/underlay",                         "rw",      "root",  "/oldroot/usr/bin/unionfs"},
	{3,        "*",                        						  "rw",      "root",  "/lib/systemd/systemd-journald"},
	{2, ""},  // Must be the last entry.
};
#endif /* PRODUCTION_MODE */

#endif

