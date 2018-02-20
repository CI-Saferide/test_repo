#ifndef SR_EVENT_RECEIVER_H
#define SR_EVENT_RECEIVER_H

#define SR_CONNGRAPH_CONF_FILE "./conngraph.conf"
enum ml_mode_t {
	ML_MODE_LEARN, 
	ML_MODE_DETECT
	//TODO: maybe ML_MODE_PROTECT ? ML_MODE_MIXED ?
};
void sr_event_receiver(SR_8 *msg_buff, SR_U32 msg_len);

SR_32 get_sr_ml_mode(void);

#endif /* SR_EVENT_RECEIVER_H */
