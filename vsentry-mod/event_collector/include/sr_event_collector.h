#ifndef SR_EVENT_COLLECTOR_H
#define SR_EVENT_COLLECTOR_H

#include "sr_types.h"
#include "sal_bitops.h"
#include "sr_sal_common.h"
#include "sr_ec_common.h"

#define SR_EC_SAMPLE_PERIOD 10000000 // 0.01 second - sample 100 times per second.

SR_32 sr_event_collector_init(void);
void sr_event_collector_uninit(void);
int sr_ec_send_event(SR_U8 buf_type, SR_U8 event_type, void *data);
void sr_ec_append_event(SR_U8 buf_type, SR_U8 event_type, void *sample_data, SR_U32 data_length, SR_BOOL is_lock);
SR_BOOL get_collector_state(void);
SR_32 sr_collector_handle_message(struct sr_ec_msg *msg);

#endif
