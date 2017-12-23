#define LOG_UPLOAD_INTERVAL 1 /*in secs*/
#define MAX_LOG_BUFFER_SIZE 0x2000

SR_32 sr_log_uploader_init(void);
SR_32 sr_log_uploader_deinit(void);

