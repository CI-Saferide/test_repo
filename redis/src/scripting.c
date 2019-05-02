/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "server.h"
#include "sha1.h"
#include "rand.h"
#include "cluster.h"

#include <ctype.h>
#include <math.h>

void ldbInit(void);
void ldbEnable(client *c);
void evalGenericCommandWithDebugging(client *c);
void ldbLog(sds entry);
void ldbLogRedisReply(char *reply);

/* Debugger shared state is stored inside this global structure. */
#define LDB_BREAKPOINTS_MAX 64  /* Max number of breakpoints. */
#define LDB_MAX_LEN_DEFAULT 256 /* Default len limit for replies / var dumps. */
struct ldbState {
    int fd;     /* Socket of the debugging client. */
    int active; /* Are we debugging EVAL right now? */
    int forked; /* Is this a fork()ed debugging session? */
    list *logs; /* List of messages to send to the client. */
    list *traces; /* Messages about Redis commands executed since last stop.*/
    list *children; /* All forked debugging sessions pids. */
    int bp[LDB_BREAKPOINTS_MAX]; /* An array of breakpoints line numbers. */
    int bpcount; /* Number of valid entries inside bp. */
    int step;   /* Stop at next line ragardless of breakpoints. */
    sds *src;   /* Lua script source code split by line. */
    int lines;  /* Number of lines in 'src'. */
    int currentline;    /* Current line number. */
    sds cbuf;   /* Debugger client command buffer. */
    size_t maxlen;  /* Max var dump / reply length. */
    int maxlen_hint_sent; /* Did we already hint about "set maxlen"? */
} ldb;

/* ---------------------------------------------------------------------------
 * Utility functions.
 * ------------------------------------------------------------------------- */

/* Perform the SHA1 of the input string. We use this both for hashing script
 * bodies in order to obtain the Lua function name, and in the implementation
 * of redis.sha1().
 *
 * 'digest' should point to a 41 bytes buffer: 40 for SHA1 converted into an
 * hexadecimal number, plus 1 byte for null term. */
void sha1hex(char *digest, char *script, size_t len) {
    SHA1_CTX ctx;
    unsigned char hash[20];
    char *cset = "0123456789abcdef";
    int j;

    SHA1Init(&ctx);
    SHA1Update(&ctx,(unsigned char*)script,len);
    SHA1Final(hash,&ctx);

    for (j = 0; j < 20; j++) {
        digest[j*2] = cset[((hash[j]&0xF0)>>4)];
        digest[j*2+1] = cset[(hash[j]&0xF)];
    }
    digest[40] = '\0';
}

/* Initialize Lua debugger data structures. */
void ldbInit(void) {
    ldb.fd = -1;
    ldb.active = 0;
    ldb.logs = listCreate();
    listSetFreeMethod(ldb.logs,(void (*)(void*))sdsfree);
    ldb.children = listCreate();
    ldb.src = NULL;
    ldb.lines = 0;
    ldb.cbuf = sdsempty();
}

/* Remove all the pending messages in the specified list. */
void ldbFlushLog(list *log) {
    listNode *ln;

    while((ln = listFirst(log)) != NULL)
        listDelNode(log,ln);
}

/* Enable debug mode of Lua scripts for this client. */
void ldbEnable(client *c) {
    ldbFlushLog(ldb.logs);
    ldb.fd = c->fd;
    ldb.step = 1;
    ldb.bpcount = 0;
    sdsfree(ldb.cbuf);
    ldb.cbuf = sdsempty();
    ldb.maxlen = LDB_MAX_LEN_DEFAULT;
    ldb.maxlen_hint_sent = 0;
}

/* Append a log entry to the specified LDB log. */
void ldbLog(sds entry) {
    listAddNodeTail(ldb.logs,entry);
}

/* A version of ldbLog() which prevents producing logs greater than
 * ldb.maxlen. The first time the limit is reached an hint is generated
 * to inform the user that reply trimming can be disabled using the
 * debugger "maxlen" command. */
void ldbLogWithMaxLen(sds entry) {
    int trimmed = 0;
    if (ldb.maxlen && sdslen(entry) > ldb.maxlen) {
        sdsrange(entry,0,ldb.maxlen-1);
        entry = sdscatlen(entry," ...",4);
        trimmed = 1;
    }
    ldbLog(entry);
    if (trimmed && ldb.maxlen_hint_sent == 0) {
        ldb.maxlen_hint_sent = 1;
        ldbLog(sdsnew(
        "<hint> The above reply was trimmed. Use 'maxlen 0' to disable trimming."));
    }
}

/* Send ldb.logs to the debugging client as a multi-bulk reply
 * consisting of simple strings. Log entries which include newlines have them
 * replaced with spaces. The entries sent are also consumed. */
void ldbSendLogs(void) {
    sds proto = sdsempty();
    proto = sdscatfmt(proto,"*%i\r\n", (int)listLength(ldb.logs));
    while(listLength(ldb.logs)) {
        listNode *ln = listFirst(ldb.logs);
        proto = sdscatlen(proto,"+",1);
        sdsmapchars(ln->value,"\r\n","  ",2);
        proto = sdscatsds(proto,ln->value);
        proto = sdscatlen(proto,"\r\n",2);
        listDelNode(ldb.logs,ln);
    }
    if (write(ldb.fd,proto,sdslen(proto)) == -1) {
        /* Avoid warning. We don't check the return value of write()
         * since the next read() will catch the I/O error and will
         * close the debugging session. */
    }
    sdsfree(proto);
}

/* Start a debugging session before calling EVAL implementation.
 * The techique we use is to capture the client socket file descriptor,
 * in order to perform direct I/O with it from within Lua hooks. This
 * way we don't have to re-enter Redis in order to handle I/O.
 *
 * The function returns 1 if the caller should proceed to call EVAL,
 * and 0 if instead the caller should abort the operation (this happens
 * for the parent in a forked session, since it's up to the children
 * to continue, or when fork returned an error).
 *
 * The caller should call ldbEndSession() only if ldbStartSession()
 * returned 1. */
int ldbStartSession(client *c) {
    ldb.forked = 1;
    if (ldb.forked) {
        pid_t cp = fork();
        if (cp == -1) {
            addReplyError(c,"Fork() failed: can't run EVAL in debugging mode.");
            return 0;
        } else if (cp == 0) {
            /* Child. Let's ignore important signals handled by the parent. */
            struct sigaction act;
            sigemptyset(&act.sa_mask);
            act.sa_flags = 0;
            act.sa_handler = SIG_IGN;
            sigaction(SIGTERM, &act, NULL);
            sigaction(SIGINT, &act, NULL);

            /* Log the creation of the child and close the listening
             * socket to make sure if the parent crashes a reset is sent
             * to the clients. */
            serverLog(LL_WARNING,"Redis forked for debugging eval");
            closeListeningSockets(0);
        } else {
            /* Parent */
            listAddNodeTail(ldb.children,(void*)(unsigned long)cp);
            freeClientAsync(c); /* Close the client in the parent side. */
            return 0;
        }
    } else {
        serverLog(LL_WARNING,
            "Redis synchronous debugging eval session started");
    }

    /* Setup our debugging session. */
    anetBlock(NULL,ldb.fd);
    anetSendTimeout(NULL,ldb.fd,5000);
    ldb.active = 1;

    /* First argument of EVAL is the script itself. We split it into different
     * lines since this is the way the debugger accesses the source code. */
    sds srcstring = sdsdup(c->argv[1]->ptr);
    size_t srclen = sdslen(srcstring);
    while(srclen && (srcstring[srclen-1] == '\n' ||
                     srcstring[srclen-1] == '\r'))
    {
        srcstring[--srclen] = '\0';
    }
    sdssetlen(srcstring,srclen);
    ldb.src = sdssplitlen(srcstring,sdslen(srcstring),"\n",1,&ldb.lines);
    sdsfree(srcstring);
    return 1;
}

/* End a debugging session after the EVAL call with debugging enabled
 * returned. */
void ldbEndSession(client *c) {
    /* Emit the remaining logs and an <endsession> mark. */
    ldbLog(sdsnew("<endsession>"));
    ldbSendLogs();

    /* If it's a fork()ed session, we just exit. */
    if (ldb.forked) {
        writeToClient(c->fd, c, 0);
        serverLog(LL_WARNING,"Lua debugging session child exiting");
        exitFromChild(0);
    } else {
        serverLog(LL_WARNING,
            "Redis synchronous debugging eval session ended");
    }

    /* Otherwise let's restore client's state. */
    anetNonBlock(NULL,ldb.fd);
    anetSendTimeout(NULL,ldb.fd,0);

    /* Close the client connectin after sending the final EVAL reply
     * in order to signal the end of the debugging session. */
    c->flags |= CLIENT_CLOSE_AFTER_REPLY;

    /* Cleanup. */
    sdsfreesplitres(ldb.src,ldb.lines);
    ldb.lines = 0;
    ldb.active = 0;
}

/* If the specified pid is among the list of children spawned for
 * forked debugging sessions, it is removed from the children list.
 * If the pid was found non-zero is returned. */
int ldbRemoveChild(pid_t pid) {
    listNode *ln = listSearchKey(ldb.children,(void*)(unsigned long)pid);
    if (ln) {
        listDelNode(ldb.children,ln);
        return 1;
    }
    return 0;
}

/* Return the number of children we still did not receive termination
 * acknowledge via wait() in the parent process. */
int ldbPendingChildren(void) {
    return listLength(ldb.children);
}

/* Kill all the forked sessions. */
void ldbKillForkedSessions(void) {
    listIter li;
    listNode *ln;

    listRewind(ldb.children,&li);
    while((ln = listNext(&li))) {
        pid_t pid = (unsigned long) ln->value;
        serverLog(LL_WARNING,"Killing debugging session %ld",(long)pid);
        kill(pid,SIGKILL);
    }
    listRelease(ldb.children);
    ldb.children = listCreate();
}

/* Wrapper for EVAL / EVALSHA that enables debugging, and makes sure
 * that when EVAL returns, whatever happened, the session is ended. */
void evalGenericCommandWithDebugging(client *c) {
    if (ldbStartSession(c)) {
        ldbEndSession(c);
    }
}

/* Return a pointer to ldb.src source code line, considering line to be
 * one-based, and returning a special string for out of range lines. */
char *ldbGetSourceLine(int line) {
    int idx = line-1;
    if (idx < 0 || idx >= ldb.lines) return "<out of range source code line>";
    return ldb.src[idx];
}

/* Return true if there is a breakpoint in the specified line. */
int ldbIsBreakpoint(int line) {
    int j;

    for (j = 0; j < ldb.bpcount; j++)
        if (ldb.bp[j] == line) return 1;
    return 0;
}

/* Add the specified breakpoint. Ignore it if we already reached the max.
 * Returns 1 if the breakpoint was added (or was already set). 0 if there is
 * no space for the breakpoint or if the line is invalid. */
int ldbAddBreakpoint(int line) {
    if (line <= 0 || line > ldb.lines) return 0;
    if (!ldbIsBreakpoint(line) && ldb.bpcount != LDB_BREAKPOINTS_MAX) {
        ldb.bp[ldb.bpcount++] = line;
        return 1;
    }
    return 0;
}

/* Remove the specified breakpoint, returning 1 if the operation was
 * performed or 0 if there was no such breakpoint. */
int ldbDelBreakpoint(int line) {
    int j;

    for (j = 0; j < ldb.bpcount; j++) {
        if (ldb.bp[j] == line) {
            ldb.bpcount--;
            memmove(ldb.bp+j,ldb.bp+j+1,ldb.bpcount-j);
            return 1;
        }
    }
    return 0;
}

/* Expect a valid multi-bulk command in the debugging client query buffer.
 * On success the command is parsed and returned as an array of SDS strings,
 * otherwise NULL is returned and there is to read more buffer. */
sds *ldbReplParseCommand(int *argcp) {
    sds *argv = NULL;
    int argc = 0;
    if (sdslen(ldb.cbuf) == 0) return NULL;

    /* Working on a copy is simpler in this case. We can modify it freely
     * for the sake of simpler parsing. */
    sds copy = sdsdup(ldb.cbuf);
    char *p = copy;

    /* This Redis protocol parser is a joke... just the simplest thing that
     * works in this context. It is also very forgiving regarding broken
     * protocol. */

    /* Seek and parse *<count>\r\n. */
    p = strchr(p,'*'); if (!p) goto protoerr;
    char *plen = p+1; /* Multi bulk len pointer. */
    p = strstr(p,"\r\n"); if (!p) goto protoerr;
    *p = '\0'; p += 2;
    *argcp = atoi(plen);
    if (*argcp <= 0 || *argcp > 1024) goto protoerr;

    /* Parse each argument. */
    argv = zmalloc(sizeof(sds)*(*argcp));
    argc = 0;
    while(argc < *argcp) {
        if (*p != '$') goto protoerr;
        plen = p+1; /* Bulk string len pointer. */
        p = strstr(p,"\r\n"); if (!p) goto protoerr;
        *p = '\0'; p += 2;
        int slen = atoi(plen); /* Length of this arg. */
        if (slen <= 0 || slen > 1024) goto protoerr;
        argv[argc++] = sdsnewlen(p,slen);
        p += slen; /* Skip the already parsed argument. */
        if (p[0] != '\r' || p[1] != '\n') goto protoerr;
        p += 2; /* Skip \r\n. */
    }
    sdsfree(copy);
    return argv;

protoerr:
    sdsfreesplitres(argv,argc);
    sdsfree(copy);
    return NULL;
}

/* Log the specified line in the Lua debugger output. */
void ldbLogSourceLine(int lnum) {
    char *line = ldbGetSourceLine(lnum);
    char *prefix;
    int bp = ldbIsBreakpoint(lnum);
    int current = ldb.currentline == lnum;

    if (current && bp)
        prefix = "->#";
    else if (current)
        prefix = "-> ";
    else if (bp)
        prefix = "  #";
    else
        prefix = "   ";
    sds thisline = sdscatprintf(sdsempty(),"%s%-3d %s", prefix, lnum, line);
    ldbLog(thisline);
}

/* Implement the "list" command of the Lua debugger. If around is 0
 * the whole file is listed, otherwise only a small portion of the file
 * around the specified line is shown. When a line number is specified
 * the amonut of context (lines before/after) is specified via the
 * 'context' argument. */
void ldbList(int around, int context) {
    int j;

    for (j = 1; j <= ldb.lines; j++) {
        if (around != 0 && abs(around-j) > context) continue;
        ldbLogSourceLine(j);
    }
}

char *ldbRedisProtocolToHuman_Int(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Bulk(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Status(sds *o, char *reply);
char *ldbRedisProtocolToHuman_MultiBulk(sds *o, char *reply);

/* Get Redis protocol from 'reply' and appends it in human readable form to
 * the passed SDS string 'o'.
 *
 * Note that the SDS string is passed by reference (pointer of pointer to
 * char*) so that we can return a modified pointer, as for SDS semantics. */
char *ldbRedisProtocolToHuman(sds *o, char *reply) {
    char *p = reply;
    switch(*p) {
    case ':': p = ldbRedisProtocolToHuman_Int(o,reply); break;
    case '$': p = ldbRedisProtocolToHuman_Bulk(o,reply); break;
    case '+': p = ldbRedisProtocolToHuman_Status(o,reply); break;
    case '-': p = ldbRedisProtocolToHuman_Status(o,reply); break;
    case '*': p = ldbRedisProtocolToHuman_MultiBulk(o,reply); break;
    }
    return p;
}

/* The following functions are helpers for ldbRedisProtocolToHuman(), each
 * take care of a given Redis return type. */

char *ldbRedisProtocolToHuman_Int(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    *o = sdscatlen(*o,reply+1,p-reply-1);
    return p+2;
}

char *ldbRedisProtocolToHuman_Bulk(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long bulklen;

    string2ll(reply+1,p-reply-1,&bulklen);
    if (bulklen == -1) {
        *o = sdscatlen(*o,"NULL",4);
        return p+2;
    } else {
        *o = sdscatrepr(*o,p+2,bulklen);
        return p+2+bulklen+2;
    }
}

char *ldbRedisProtocolToHuman_Status(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');

    *o = sdscatrepr(*o,reply,p-reply);
    return p+2;
}

char *ldbRedisProtocolToHuman_MultiBulk(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long mbulklen;
    int j = 0;

    string2ll(reply+1,p-reply-1,&mbulklen);
    p += 2;
    if (mbulklen == -1) {
        *o = sdscatlen(*o,"NULL",4);
        return p;
    }
    *o = sdscatlen(*o,"[",1);
    for (j = 0; j < mbulklen; j++) {
        p = ldbRedisProtocolToHuman(o,p);
        if (j != mbulklen-1) *o = sdscatlen(*o,",",1);
    }
    *o = sdscatlen(*o,"]",1);
    return p;
}

/* Log a Redis reply as debugger output, in an human readable format.
 * If the resulting string is longer than 'len' plus a few more chars
 * used as prefix, it gets truncated. */
void ldbLogRedisReply(char *reply) {
    sds log = sdsnew("<reply> ");
    ldbRedisProtocolToHuman(&log,reply);
    ldbLogWithMaxLen(log);
}

/* Implements the break command to list, add and remove breakpoints. */
void ldbBreak(sds *argv, int argc) {
    if (argc == 1) {
        if (ldb.bpcount == 0) {
            ldbLog(sdsnew("No breakpoints set. Use 'b <line>' to add one."));
            return;
        } else {
            ldbLog(sdscatfmt(sdsempty(),"%i breakpoints set:",ldb.bpcount));
            int j;
            for (j = 0; j < ldb.bpcount; j++)
                ldbLogSourceLine(ldb.bp[j]);
        }
    } else {
        int j;
        for (j = 1; j < argc; j++) {
            char *arg = argv[j];
            long line;
            if (!string2l(arg,sdslen(arg),&line)) {
                ldbLog(sdscatfmt(sdsempty(),"Invalid argument:'%s'",arg));
            } else {
                if (line == 0) {
                    ldb.bpcount = 0;
                    ldbLog(sdsnew("All breakpoints removed."));
                } else if (line > 0) {
                    if (ldb.bpcount == LDB_BREAKPOINTS_MAX) {
                        ldbLog(sdsnew("Too many breakpoints set."));
                    } else if (ldbAddBreakpoint(line)) {
                        ldbList(line,1);
                    } else {
                        ldbLog(sdsnew("Wrong line number."));
                    }
                } else if (line < 0) {
                    if (ldbDelBreakpoint(-line))
                        ldbLog(sdsnew("Breakpoint removed."));
                    else
                        ldbLog(sdsnew("No breakpoint in the specified line."));
                }
            }
        }
    }
}

/* Impleemnts the debugger "maxlen" command. It just queries or sets the
 * ldb.maxlen variable. */
void ldbMaxlen(sds *argv, int argc) {
    if (argc == 2) {
        int newval = atoi(argv[1]);
        ldb.maxlen_hint_sent = 1; /* User knows about this command. */
        if (newval != 0 && newval <= 60) newval = 60;
        ldb.maxlen = newval;
    }
    if (ldb.maxlen) {
        ldbLog(sdscatprintf(sdsempty(),"<value> replies are truncated at %d bytes.",(int)ldb.maxlen));
    } else {
        ldbLog(sdscatprintf(sdsempty(),"<value> replies are unlimited."));
    }
}

