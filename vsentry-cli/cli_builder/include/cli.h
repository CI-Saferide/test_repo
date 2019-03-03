#ifndef CLI_H
#define CLI_H

#define CLI_SUCCESS 0
#define CLI_ERROR  -1

typedef struct {
        void (*help_cb)(void);
        void (*run_cb)(char *buf);
} node_operations_t;

int cli_init(char *buf);
void cli_run(void);
void cli_set_run(int i_is_run);
int cli_register_operatios(char *path, node_operations_t *operation);
void cli_error(char *msg, int is_nl);
void cli_notify_info(char *msg);
char *cli_get_string_user_input(int is_current, char *def_val, char *prompt, int (*is_valid_cb)(char *data), void (*help_cb)(void));

#endif
