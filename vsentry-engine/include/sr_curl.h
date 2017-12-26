#ifndef __SR_CURL__
#define __SR_CURL__

#include <curl/curl.h>

#define XVIN "X-VIN: 1234512345abcdef"

struct curl_fetch_st {
    char *payload;
    size_t size;
};

#define SR_CURL_INIT(i_url) \
	curl_global_init(CURL_GLOBAL_DEFAULT); \
	curl = curl_easy_init(); \
        if (!curl) { \
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,  "curl_easy_init:"); \
                return SR_ERROR; \
        } \
        curl_easy_setopt(curl, CURLOPT_URL, i_url);

#define SR_CURL_DEINIT(i_curl) \
	curl_easy_cleanup(i_curl); \
        curl_global_cleanup();


static inline size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
      fprintf(stderr, "ERROR: Failed to expand buffer in curl_callback");
      free(p->payload);
      return -1;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

#endif
