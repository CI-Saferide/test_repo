#ifndef __SR_CONF__
#define __SR_CONF__

static char *filename = "sr_config.cfg";

#define CONFD_SERVER "127.0.0.1"
#define CONFD_CONFIG_PATH_PREFIX "/config"
#define CONFD_CONTROL_PATH_PREFIX "/control"
        
#define IF_NAME_SIZE            32
#define ENGINE_NAME_SIZE        32
#define ACTION_NAME_SIZE        32
#define ACTION_STR_SIZE         32
#define USER_NAME_SIZE          128
#define PROG_NAME_SIZE          256
#define FILE_NAME_SIZE          4096
#define FILE_PERM_SIZE          8
#define ENGINE_STATE_SIZE       16
#define ACTION_DROP "drop"
#define ACTION_ALLOW "allow"
#define ENGINE_START "start"
#define ENGINE_STOP "stop"
#define ENGINE_RELOAD "reload"

/* confd DB enums */
typedef enum {
        SR_ACTION_DROP,
        SR_ACTION_ALLOW,
        SR_ACTION_MAX = SR_ACTION_ALLOW,
        SR_ACTION_TOTAL = (SR_ACTION_MAX + 1),
} sr_action;

char* sr_action_str[SR_ACTION_TOTAL] = {
        ACTION_DROP,
        ACTION_ALLOW,
};

typedef enum {
        SR_LOG_TO_SYSLOG,
        SR_LOG_TO_FILE,
        SR_LOG_MAX = SR_LOG_TO_FILE,
        SR_LOG_TOTAL = (SR_LOG_MAX + 1),
} sr_log_facility;

char* sr_log_facility_str[SR_LOG_TOTAL] = {
        "syslog",
        "file",
};

typedef enum {
        SR_LOG_SEVERITY_CRT,
        SR_LOG_SEVERITY_ERR,
        SR_LOG_SEVERITY_WARN,
        SR_LOG_SEVERITY_INFO,
        SR_LOG_SEVERITY_DEBUG,
        SR_LOG_SEVERITY_MAX = SR_LOG_SEVERITY_DEBUG,
        SR_LOG_SEVERITY_TOTAL = (SR_LOG_SEVERITY_MAX + 1),
} sr_log_severity;

char* sr_log_severity_str[SR_LOG_SEVERITY_TOTAL] = {
        "critical",
        "error",
        "warning",
        "info",
        "debug",
};

typedef struct {
        char action_name[ACTION_NAME_SIZE];
        sr_action action;
        int is_log;
        sr_log_facility log_facility;
        sr_log_severity log_severity;
        int black_list;
        int terminate;
} sr_action_cfg;

typedef struct {
        struct in_addr srcaddr;
        struct in_addr dstaddr;
        struct in_addr srcnetmask;
        struct in_addr dstnetmask;
        unsigned short dstport;
        unsigned short srcport;
        unsigned char proto;
        char user[USER_NAME_SIZE];
        char program[PROG_NAME_SIZE];
        unsigned int max_rate;
} network_tuple;

typedef struct {
        unsigned short rulenum;
        network_tuple tuple;
        sr_action_cfg action;
} network_rule;

typedef struct {
        unsigned int msg_id;
        char user[USER_NAME_SIZE];
        char program[PROG_NAME_SIZE];
        unsigned int max_rate;
} can_tuple;

typedef struct {
        unsigned short rulenum;
        can_tuple tuple;
        sr_action_cfg action;
} can_rule;

typedef struct {
        char name[FILE_NAME_SIZE];
        char permission[FILE_PERM_SIZE];
        char user[USER_NAME_SIZE];
        char program[PROG_NAME_SIZE];
        unsigned int max_rate;
} file_tuple;

typedef struct {
        unsigned short rulenum;
        file_tuple tuple;
        sr_action_cfg action;
} file_rule;

#endif
