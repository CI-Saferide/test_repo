#ifndef _MULTIPLEXER_H
#define _MULTIPLEXER_H



/* FS related functions */
typedef struct _fileinfo {
        unsigned char filename[128];
        unsigned char fullpath[128];
        unsigned long gid; /* group id */
        unsigned long tid; /* thread id */
}fileinfo;

int mpx_mkdir(fileinfo* info);


#endif /* _MULTIPLEXER_H */
