#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <semaphore.h>
#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <libgen.h>
#include "sr_log.h"
#include "sr_log_uploader.h"
#include "sr_config_parse.h"
#include <openssl/md5.h>

#define uploader_err(fmt, args...) \
    fprintf(stderr, "ERROR: %s(): " fmt, __func__, ##args)
    //CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s(): " fmt, __func__, ##args)
#define uploader_debug(fmt, args...) \
    fprintf(stderr, "DEBUG: %s(): " fmt, __func__, ##args)
    //CEF_log_event(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW, "%s(): " fmt, __func__, ##args)

static void remote_update_init(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static void remote_update_deinit(void)
{
    curl_global_cleanup(); 
}

CURL *upload_curl_handle;

struct file_state{
    FILE *file;
    size_t write_size;
};

static size_t read_callback(char *buffer, size_t size, size_t nitems, void *userp)
{
    struct file_state *ptr = (struct file_state*)userp;
    size_t written = 0;
    size_t actual_size = ptr->write_size;

    if (ptr->write_size == 0)
        return 0;

    if ((size*nitems) < actual_size)
        actual_size = (size*nitems);

    written = fread(buffer, 1, actual_size, ptr->file);

    ptr->write_size -= written;

    return written;
}

#define MAX_STR_SIZE 512

static int get_size_with_last_full_msg(FILE *logfile, int offset, int file_size)
{
    char buffer[MAX_STR_SIZE];
    int size = 0;
    int new_offset = offset;
    int ret = 0;

    /* we assume that each msg in the file will no be longer than 512 bytes */
    if ((file_size - offset) <= MAX_STR_SIZE)
        new_offset = offset;
    else
        new_offset = (file_size - MAX_STR_SIZE);

    if(fseek(logfile, new_offset, SEEK_SET) < 0) {
        uploader_err("fseek failed: %s\n", strerror(errno));
        return 0;
    }

    memset(buffer, 0, MAX_STR_SIZE);
    if ((ret = (int)fread(buffer, 1, MAX_STR_SIZE, logfile)) > 0) {
        char *tmp = strrchr(buffer, '\n');
        if (tmp)
            size = (new_offset - offset) + ((tmp - &buffer[0]) + 1);
    }

    //uploader_debug("size = %d, actual size = %d\n", size, (file_size - offset));

    return size;
}

static int upload_log_file(char* filename, int offset)
{
    FILE* logfile = NULL;
    char post_vin[64];
    CURLcode res;
    struct stat logfile_stat;
    int ret = 0, size;
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    struct curl_slist *chunk = NULL;
    struct file_state log_file_state;
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    if (!upload_curl_handle) {
        upload_curl_handle = curl_easy_init();
        if (!upload_curl_handle) {
            uploader_err("curl_easy_init failed\n");
            goto out;
        }
        /*https://stackoverflow.com/questions/9191668/error-longjmp-causes-uninitialized-stack-frame */
        curl_easy_setopt(upload_curl_handle, CURLOPT_NOSIGNAL, 1);
        //curl_easy_setopt(upload_curl_handle, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_URL, "http://saferide-log-collector-staging.eu-west-1.elasticbeanstalk.com/logs");

        snprintf(post_vin, 64, "X-VIN: %s", config_params->vin);
        chunk = curl_slist_append(chunk, post_vin);
        curl_easy_setopt(upload_curl_handle, CURLOPT_HTTPHEADER, chunk);

        curl_easy_setopt(upload_curl_handle, CURLOPT_READFUNCTION, read_callback);
    }

    logfile = fopen(filename, "rb");
    if (!logfile) {
        uploader_err("%s fopen failed: %s\n", filename, strerror(errno));
        goto out;
    }

    if (fstat(fileno(logfile), &logfile_stat)) {
        uploader_err("%s fstat failed: %s\n", filename, strerror(errno));
        goto out;
    }

    //size = (logfile_stat.st_size - offset);
    size = get_size_with_last_full_msg(logfile, offset, logfile_stat.st_size);
    if (size <= 0) {
        uploader_err("something is wrong, size is %d\n", size);
        goto out;
    }

    /* set the file offset in the last position we read from */
    if(fseek(logfile, offset, SEEK_SET) < 0) {
        uploader_err("%s fseek failed: %s\n", filename, strerror(errno));
        goto out;
    }

    log_file_state.write_size = size;
    log_file_state.file = logfile;

    curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "logs", CURLFORM_FILENAME, filename, CURLFORM_STREAM, &log_file_state, CURLFORM_CONTENTSLENGTH, size, CURLFORM_END);
    curl_easy_setopt(upload_curl_handle, CURLOPT_HTTPPOST, formpost);

    //uploader_debug("uploading %s@%d, size %d\n", filename, offset, size);

    res = curl_easy_perform(upload_curl_handle);

    if(res != CURLE_OK) {
        int http_code;
        curl_easy_getinfo (upload_curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
        uploader_err("curl_easy_perform failed: %s (%d)\n", curl_easy_strerror(res), http_code);
        goto out;
    }
    ret = size;

out:
   if (formpost)
	curl_formfree(formpost);

    if (logfile)
        fclose(logfile);

    return ret;
}

int pipe_fds[2];

/* time of last log upload */
struct timeval last_upload;
 /* offset in the log file */
static unsigned long file_offset = 0;

/* log file rotation detection params */
static bool was_moved = false;

/* TODO: set the number of files according to config file */
char **log_files;
char **full_log_files;

static int tracked_file_index = 0;

sem_t sem_log_uploader;
sem_t sem_can_log_uploader;

static void* log_uploader(void *data)
{
    struct stat log_file_stat;
    int ret = 0;
    bool *run = (bool*)data;

    while (*run) {
        sem_wait(&sem_log_uploader);

        if (!*run) {
            uploader_debug("log_uploader thread exiting ...\n");
            break;
        }

        if (stat(full_log_files[tracked_file_index], &log_file_stat)) {
            /* errors are expected ... its rotated log */
            uploader_err("stat: %s\n", strerror(errno));
            continue;
        }

        if ((tracked_file_index > 0) && (log_file_stat.st_size == file_offset)) {
            file_offset = 0;
            tracked_file_index--;
            continue;
        }

        if (log_file_stat.st_size < file_offset) {
            /* something happend .. most likely the file was
             * renamed. lets wait for the move event and
             * continue from there */
            continue;
        }

        ret = upload_log_file(full_log_files[tracked_file_index], file_offset);
        if (ret > 0) {
            file_offset += ret;
            if (tracked_file_index > 0) {
                /* in such case the file is close and will not be modified,
                 * thus we can assume that we uploaded all of it and can
                 * set file_offset to 0 */
                file_offset = 0;
                tracked_file_index--;
                uploader_debug("going back to %s\n", full_log_files[tracked_file_index]);
            }
        }
    }

    pthread_detach(pthread_self());

    uploader_debug("exit!\n");

    return NULL;
}

#define CANDUMP_FILE_NAME_LEN     512

char candump_file_name[CANDUMP_FILE_NAME_LEN] = "";
char candump_file_name_tgz[CANDUMP_FILE_NAME_LEN] = "";

void write_archive(const char *outname, char *filename)
{
    struct archive *a;
    struct archive_entry *entry;
    struct stat st;
    char buff[8192];
    int len;
    int fd;

    //uploader_debug("outname %s, filename %s\n", outname, filename);
    a = archive_write_new();
    archive_write_add_filter_gzip(a);
    archive_write_set_format_pax_restricted(a);
    archive_write_open_filename(a, outname);
    if (stat(filename, &st) < 0) {
        uploader_err("stat on %s failed: %s\n", filename, strerror(errno));
        return;
    }
    entry = archive_entry_new();
    archive_entry_set_pathname(entry, basename(filename));
    archive_entry_set_size(entry, st.st_size);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_write_header(a, entry);
    fd = open(filename, O_RDONLY);
    len = read(fd, buff, sizeof(buff));
    while ( len > 0 ) {
        archive_write_data(a, buff, len);
        len = read(fd, buff, sizeof(buff));
    }
    close(fd);
    archive_entry_free(entry);
    archive_write_close(a);
    archive_write_free(a);
}

static int can_log_upload(void)
{
    unsigned char c[MD5_DIGEST_LENGTH];
    MD5_CTX mdContext;
    int bytes;
    int i;
    unsigned char data[1024];
    char md5_str[33];
    char md5_hdr[41];
    CURL *curl;
    CURLcode res;
    struct stat file_info;
    FILE *fd;
    struct curl_slist *chunk = NULL;
    struct curl_httppost* post = NULL;
    struct curl_httppost* last = NULL;
    char post_vin[64];
    struct config_params_t *config_params;
    int rc = 0;

    config_params = sr_config_get_param();

#ifdef CAN_UPLOAD_DEBUG
	printf("can_log_upload loading :%s:\n", candump_file_name_tgz);
#endif

    fd = fopen(candump_file_name_tgz, "rb");
    if(!fd) {
        uploader_err("%s fopen failed: %s\n", candump_file_name_tgz, strerror(errno));
        return -1;
    }

    /* to get the file size */
    if(fstat(fileno(fd), &file_info) != 0) {
        uploader_err("%s fstat failed: %s\n", candump_file_name_tgz, strerror(errno));
        fclose(fd);
        return -1;
    }

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, fd)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);

    for(i = 0; i < 16; ++i)
        sprintf(&md5_str[i*2], "%02x", (unsigned int)c[i]);
    sprintf (md5_hdr, "X-CRC: %s", md5_str);

    /* starting to send the data */
    curl = curl_easy_init();
    if (curl) {
        /* upload to this place */
        curl_easy_setopt(curl, CURLOPT_URL, "saferide-can-collector.eu-west-1.elasticbeanstalk.com/can");
        //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "can",
              CURLFORM_FILE, candump_file_name_tgz, CURLFORM_END);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
        snprintf(post_vin, 64, "X-VIN: %s", config_params->vin);
        chunk = curl_slist_append(chunk, post_vin);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        chunk = curl_slist_append(chunk, md5_hdr);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK) {
            int http_code;
            curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
            uploader_err("curl_easy_perform failed: %s (%d)\n", curl_easy_strerror(res), http_code);
			rc = -1;
        }
        curl_easy_cleanup(curl);
    }

    if (chunk)
         curl_slist_free_all(chunk);
    if (post)
         curl_formfree(post);

    fclose(fd);

    return rc;
}

static void* can_log_uploader(void *data)
{
    bool *run = (bool*)data;
    int rc;
    struct config_params_t *config_params;
    DIR *dir;
    struct dirent *ent;

    config_params = sr_config_get_param();

    while (*run) {
        sem_wait(&sem_can_log_uploader);

        if (!*run) {
            uploader_debug("can_log_uploader thread exiting ...\n");
            break;
        }

	/* First look at previous files that were not sent */ 
	if (!(dir = opendir (config_params->log_path))) {
            uploader_debug("can_log_uploader Failed opening log path directory\n");
            break;
	}
 	while ((ent = readdir (dir)) != NULL) {
		if (strstr(ent->d_name, ".tgz")) {
			sprintf(candump_file_name_tgz, "%s/%s", config_params->log_path, ent->d_name);
			rc = can_log_upload();
			if (rc == 0)
        			unlink(candump_file_name_tgz);
		}
  	}
  	closedir (dir);

        snprintf(candump_file_name_tgz, CANDUMP_FILE_NAME_LEN, "%s.tgz", candump_file_name);
        /* compress the file */
        write_archive(candump_file_name_tgz, candump_file_name);

        /* upload the file */
        rc = can_log_upload();
        /* delete the files, the ziped files is deleted upon succesfful transmit */
        unlink(candump_file_name);
	if (rc == 0)
		unlink(candump_file_name_tgz);
    }

    pthread_detach(pthread_self());

    uploader_debug("exit!\n");

    return NULL;
}

static int check_log_events(int fd)
{
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len = 0;
    char *ptr = NULL;
    struct stat log_file_stat;
    struct timeval current_time;
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    memset(buf, 0, sizeof(buf));
    len = read(fd, buf, sizeof(buf));

    if (len <= 0) {
        if (len < 0)
            uploader_err("read: %s\n", strerror(errno));
        return 0;
    }

    for (ptr = buf; ptr < buf + len;
            ptr += sizeof(struct inotify_event) + event->len) {
        event = (const struct inotify_event *) ptr;
        if (!event->len)
            continue;

        /* check if this event is related to candump log file */
        if (strncmp(event->name, config_params->vin, strlen(config_params->vin)) == 0) {
            if (strcmp(event->name, basename(candump_file_name_tgz)) == 0)
                continue;

            if (event->mask == IN_MOVED_TO) {
                //uploader_debug("event name %s\n", event->name);
                snprintf(candump_file_name, CANDUMP_FILE_NAME_LEN, "%s%s",
                    config_params->log_path, event->name);
                sem_post(&sem_can_log_uploader);
                continue;
            }
        }
        /* check if this event is related to log file */
        if (strcmp(event->name, log_files[tracked_file_index]) == 0) {
            //uploader_debug("event name %s, mask = 0x%08X\n", event->name, event->mask);
            if (event->mask == IN_MODIFY) {
                bool force_upload = false;

                if (stat(full_log_files[tracked_file_index], &log_file_stat)) {
                    /* errors are expected ... its rotated log */
                    uploader_err("stat: %s\n", strerror(errno));
                    continue;
                }

                if (log_file_stat.st_size < file_offset) {
                    /* something happend .. most likely the file was
                     * renamed. lets wait for the move event and
                     * continue from there */
                    continue;
                }

                gettimeofday(&current_time, NULL);
                if ((current_time.tv_sec - last_upload.tv_sec) >= LOG_UPLOAD_INTERVAL)
                    force_upload = 1;

                if (force_upload ||
                    (log_file_stat.st_size - file_offset) >= MAX_LOG_BUFFER_SIZE) {
                    sem_post(&sem_log_uploader);
                }
            }
            if (event->mask == IN_MOVED_FROM) {
                /* do nothing .. wait for move to complete */
                uploader_debug("%s moved\n", log_files[tracked_file_index]);
                was_moved = true;
                continue;
            }
        }

        if (event->mask == IN_MOVED_TO) {
            if (was_moved) {
                if (tracked_file_index < (config_params->cef_file_cycling-1))
                    tracked_file_index++;
                uploader_debug("to %s\n", log_files[tracked_file_index]);
                was_moved = false;
                sem_post(&sem_log_uploader);
            }
        }
    }

    return 0;
}

static void* monitor_file(void *data)
{
    int fd, wd, ret;
    fd_set rfds;
    unsigned int notify_mask = (IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE);
    pthread_t thread_id;
    bool run = true;
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    /* create the file descriptor for accessing the inotify API */
    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        uploader_err("inotify_init1 failed: %s\n", strerror(errno));
        return NULL;
    }

    uploader_debug("watching %s\n", config_params->CEF_log_path);
    /* start watching events on the log files */
    wd = inotify_add_watch(fd, config_params->CEF_log_path, notify_mask);
    if (wd == -1) {
        uploader_err("Cannot watch %s: %s\n", config_params->CEF_log_path, strerror(errno));
        return NULL;
    }

    uploader_debug("watching %s\n", config_params->log_path);
    wd = inotify_add_watch(fd, config_params->log_path, notify_mask);
    if (wd == -1) {
        uploader_err("Cannot watch %s: %s\n", config_params->log_path, strerror(errno));
        return NULL;
    }

    sem_init(&sem_log_uploader, 0, 0);
    sem_init(&sem_can_log_uploader, 0, 0);

    /* start the log uploader thread */
    ret = pthread_create(&thread_id, NULL, &log_uploader, &run);
    if (ret != 0) {
        uploader_err("pthread_create: %s\n", strerror(errno));
        return NULL;
    }

    ret = pthread_create(&thread_id, NULL, &can_log_uploader, &run);
    if (ret != 0) {
        uploader_err("pthread_create: %s\n", strerror(errno));
        return NULL;
    }

    while (true) {
        FD_ZERO(&rfds);

        /* watch for file event or on the pipe (i.e. exit) without timeout */
        FD_SET(fd, &rfds);
        FD_SET(pipe_fds[0], &rfds);

        ret = select((MAX(fd,pipe_fds[0]) + 1), &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            uploader_err("select failed: %s\n", strerror(ret));
            continue;
        }
        if (FD_ISSET(pipe_fds[0] , &rfds)) {
            /* event on pipe .. we need to exit */
            uploader_debug("monitor_file exit\n");
            run = false;
            sem_post(&sem_log_uploader);
            sem_post(&sem_can_log_uploader);
            break;
        }

        if (ret > 0) {
            check_log_events(fd);
        } else if (ret < 0)
            uploader_err("select failed: %s\n", strerror(ret));
    }

    close(fd);

    pthread_detach(pthread_self());

    uploader_debug("exit!\n");

    return NULL;
}

int sr_log_uploader_init(void)
{
    int i;
    struct stat log_file_stat;
    pthread_t thread_id;
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    if (config_params->cef_file_cycling <= 0) {
        uploader_err("wrong cycling number: %d\n", config_params->cef_file_cycling);
        return SR_ERROR;
    }

    if (strlen(config_params->CEF_log_path) <= 0) {
        uploader_err("log file directory was not set\n");
        return SR_ERROR;
    }

    if ( pipe(pipe_fds) < 0){
        uploader_err("pipe failed %s\n", strerror(errno));
        exit(1);
    }

    log_files = malloc(config_params->cef_file_cycling * sizeof(char*));
    full_log_files = malloc(config_params->cef_file_cycling * sizeof(char*));
    
    for (i = 0; i < config_params->cef_file_cycling; i++) {
        log_files[i] = malloc(PATH_BUFF);
        if (!log_files[i]) {
            uploader_err("log_files[%d] malloc failed\n", i);
            return SR_ERROR;
        }
        snprintf(log_files[i], PATH_BUFF, "%s%d%s", LOG_CEF_PREFIX, i, LOG_CEF_SUFFIX);

        full_log_files[i] = malloc(PATH_BUFF);
        if (!full_log_files) {
            uploader_err("full_log_files[%d] malloc failed\n", i);
            return SR_ERROR;
        }
        sprintf(full_log_files[i], "%s%s%d%s",config_params->CEF_log_path, LOG_CEF_PREFIX, i, LOG_CEF_SUFFIX);
    }

    tracked_file_index = 0;
    uploader_debug("reading logs from %s\n", log_files[0]);

    /* init libcurl */
    remote_update_init();

    /* set the last timestamp we considered as the last log uplod was */
    gettimeofday(&last_upload, NULL);

    /* get the current file offset */
    if (stat(full_log_files[0], &log_file_stat)) {
        uploader_err("stat: %s\n", strerror(errno));
        return SR_ERROR;
    }
    file_offset = log_file_stat.st_size;

    if (pthread_create(&thread_id, NULL, &monitor_file, NULL) != 0) {
        uploader_err("pthread_create: %s\n", strerror(errno));
        sr_log_uploader_deinit();
        return SR_ERROR;
    }

    return SR_SUCCESS;
}

int sr_log_uploader_deinit(void)
{
    int i;
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    if (write(pipe_fds[1], "STOP", 4) < 0)
        uploader_err("failed writing to pipe: %s\n", strerror(errno));

    remote_update_deinit();

    for (i=0; i<config_params->cef_file_cycling; i++) {
        free(log_files[i]);
        free(full_log_files[i]);
    }

    free(log_files);
    free(full_log_files);

    return SR_SUCCESS;
}
 
