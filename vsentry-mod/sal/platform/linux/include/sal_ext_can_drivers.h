#ifndef SAL_EXT_CAN_DRIVERS_H
#define SAL_EXT_CAN_DRIVERS_H

typedef int (*security_cb_t)(u32 msg_id, int is_dir_in, int can_dev_id);
int security_cb_register(security_cb_t i_scurity_cb);

#endif
