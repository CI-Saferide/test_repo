#ifndef SR_CLS_CANBUS_CONTROL_H
#define SR_CLS_CANBUS_CONTROL_H

extern SR_32 sr_ml_mode;
#define SR_CONNGRAPH_CONF_FILE "./conngraph.conf"
enum ml_mode_t {
	ML_MODE_LEARN, 
	ML_MODE_DETECT
	//TODO: maybe ML_MODE_PROTECT ? ML_MODE_MIXED ?
};
int sr_cls_canid_add_rule(SR_U32 canid, SR_U32 rulenum);
int sr_cls_canid_del_rule(SR_U32 canid, SR_U32 rulenum);

#endif /* SR_CLS_CANBUS_CONTROL_H */
