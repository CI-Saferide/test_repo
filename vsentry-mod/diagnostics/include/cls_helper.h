/* file: cls_helper.h
 * purpose: this file is used by all sysfs subjects for vsentry classifier
*/
#include "sal_module.h"
#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_actions_common.h"
#include "sr_classifier.h"
#include "sr_actions_common.h"

#define HT_canid_SIZE 32
#define HT_PORT_SIZE 32
#define EXEC_FILE_HASH_TABLE_SIZE 8192
#define UID_HASH_TABLE_SIZE 32
#define MAX_NUM_OF_LOCAL_IPS 10

extern unsigned char buf[SR_MAX_PATH];

size_t write_to_user(char __user *user_buf, size_t count, loff_t *ppos, size_t len, size_t *used_count);
SR_U32 get_exec_for_rule(struct sr_hash_table_t *table,SR_16 rule,SR_32 table_size,enum sr_rule_type type);
SR_U32 get_uid_for_rule(struct sr_hash_table_t *table,SR_16 rule,SR_32 table_size,enum sr_rule_type type);
