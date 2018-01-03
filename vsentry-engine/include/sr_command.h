#ifndef __SR_COMMAND_H__
#define __SR_COMMAND_H__
	
SR_32 sr_get_command_start(void);
void sr_get_command_stop(void);
void sr_command_get_ml_state_str(char *state, SR_U32 size);
void sr_command_get_state_str(char *state, SR_U32 size);

#endif
