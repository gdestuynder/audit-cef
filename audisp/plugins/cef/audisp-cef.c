/* audisp-cef.c --
 * Copyright (c) 2012 Mozilla Corporation.
 * Portions Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Guillaume Destuynder <gdestuynder@mozilla.com>
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <time.h>
#include "libaudit.h"
#include "auparse.h"
#include "private.h"
#include "cef-config.h"

#define CONFIG_FILE "/etc/audisp/audisp-cef.conf"
//This is the maximum arg len for commands before truncating. Syslog often will otherwise truncate the msg.
#define MAX_ARG_LEN 512
#define BUF_SIZE 32

static volatile int stop = 0;
static volatile int hup = 0;
static cef_conf_t config;
static char *hostname = NULL;
static auparse_state_t *au = NULL;
static struct passwd pwd;
static char *buf;
static size_t bufsize;
static int machine = -1;

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

static void term_handler( int sig )
{
	stop = 1;
}

static void hup_handler( int sig )
{
	hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

/* find string distance from *in until char c is reached */
unsigned int strstok(char *in, char c)
{
	unsigned int slen, len = 0;

	if (in == NULL)
		return len;

	slen = strlen(in);

	while (in[len] != c && len <= slen)
		len++;
	len++;
	return len;
}

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH];
	struct sigaction sa;
	struct utsname uts;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;

	uname(&uts);
	hostname = (char *)malloc(sizeof(uts.nodename));
	sprintf(hostname, "%s", uts.nodename);

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 16384;
	buf = (char *)malloc(bufsize);

	if (load_config(&config, CONFIG_FILE))
		return 1;

	openlog("audit-cef", LOG_CONS, config.facility);

	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		syslog(LOG_ERR, "could not initialize auparse");
		free_config(&config);
		return -1;
	}
   
   machine = audit_detect_machine();
   if (machine < 0)
       return -1;

	auparse_add_callback(au, handle_event, NULL, NULL);

	syslog(LOG_INFO, "audisp-cef loaded\n");
	do {
		if (hup)
			reload_config();

		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0)
			auparse_feed(au, tmp, strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH));

		if (feof(stdin))
			break;
	} while (stop == 0);

	auparse_flush_feed(au);
	auparse_destroy(au);
	free(hostname);
	free(buf);
	syslog(LOG_INFO, "audisp-cef unloaded\n");
	closelog();

	return 0;
}

/*
 * This function seeks to the specified record returning its type on succees
 */
static int goto_record_type(auparse_state_t *au, int type)
{
	int cur_type;

	auparse_first_record(au);
	do {
		cur_type = auparse_get_type(au);
		if (cur_type == type) {
			auparse_first_field(au);
			return type;  // Normal exit
		}
	} while (auparse_next_record(au) > 0);

	return -1;
}

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, rc, num=0;
	time_t au_time;
	const char *key = NULL, *ppid = NULL, *pid = NULL, *auid = NULL, *uid = NULL, *gid = NULL, *euid = NULL, *suid = NULL;
	const char *fsuid = NULL, *egid = NULL, *sgid = NULL, *fsgid = NULL, *tty = NULL, *exe = NULL, *ses = NULL;
	const char *cwd = NULL, *argc = NULL, *cmd = NULL;
	const char *syscall = NULL;
	const char *fname = NULL, *inode = NULL, *dev = NULL, *mode = NULL, *ouid = NULL, *ogid = NULL, *rdev = NULL;
	char fullcmd[MAX_ARG_LEN+1] = "\0";
	char fullcmdt[5] = "No\0";
	char extra[1024] = "\0";
	char extrat[5] = "No\0";
   const char *sys;
	int extralen = 0;

	char msgname[16] = "\0", msgdesc[32] = "\0";
	char sppid[256], ppid_p[1024];
	FILE *fp;

	char f[8];
	int len, tmplen;
	int argcount, i;
	struct passwd *result;
	int havecef = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	pwd.pw_name = NULL;

	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		rc = 0;
		auparse_first_field(au);
		au_time = auparse_get_time(au);
		switch (type) {
			case AUDIT_EXECVE:
				argc = auparse_find_field(au, "argc");
				if (argc)
					argcount = auparse_get_field_int(au);
				else
					argcount = 0;
				fullcmd[0] = '\0';
				len = 0;
				for (i = 0; i != argcount; i++) {
					goto_record_type(au, type);
					tmplen = snprintf(f, 7, "a%d", i);
					f[tmplen] = '\0';
					cmd = auparse_find_field(au, f);
					cmd = auparse_interpret_field(au);
					if (!cmd)
						continue;
					if (MAX_ARG_LEN-strlen(fullcmd) > strlen(cmd))
						if (len == 0)
							len += sprintf(fullcmd+len, "%s", cmd);
						else
							len += sprintf(fullcmd+len, " %s", cmd);
					else
						strncpy(fullcmdt, "Yes\0", 4);
				}
				break;
			case AUDIT_CWD:
				cwd = auparse_find_field(au, "cwd");
				if (cwd)
					auparse_interpret_field(au);
				if (extralen == 0)
					extralen += snprintf(extra+extralen, 1024, "cwd\\=%s", cwd);
				else
					extralen += snprintf(extra+extralen, 1024, " cwd\\=%s", cwd);
				break;
			case AUDIT_PATH:
				fname = auparse_find_field(au, "name");
				goto_record_type(au, type);
				inode = auparse_find_field(au, "inode");
				goto_record_type(au, type);
				inode = auparse_find_field(au, "dev");
				goto_record_type(au, type);
				inode = auparse_find_field(au, "mode");
				goto_record_type(au, type);
				inode = auparse_find_field(au, "ouid");
				goto_record_type(au, type);
				inode = auparse_find_field(au, "ogid");
				goto_record_type(au, type);
				inode = auparse_find_field(au, "rdev");
				goto_record_type(au, type);
				if (extralen == 0) {
					extralen += snprintf(extra+extralen, 1024, "inode\\=%s dev\\=%s mode\\=%s ouid\\=%s ogid\\=%s rdev\\=%s",
						inode, dev, mode, ouid, ogid, rdev);
				} else {
					extralen += snprintf(extra+extralen, 1024, " inode\\=%s dev\\=%s mode\\=%s ouid\\=%s ogid\\=%s rdev\\=%s",
						inode, dev, mode, ouid, ogid, rdev);
				}
				break;
			case AUDIT_SYSCALL:
				syscall = auparse_find_field(au, "syscall");
				if (!syscall)
					return;
				i = auparse_get_field_int(au);
               sys = audit_syscall_to_name(i, machine);
               if (!sys) {
                   syslog(LOG_INFO, "Unknown system call %u", i);
                   return;
               }

               if (!strncmp(sys, "write", 5) || !strncmp(sys, "open", 4) || \
                   !strncmp(sys, "unlink", 6)) {
					havecef = i;
					strncpy(msgname, "WRITE\0", 6);
					strncpy(msgdesc, "Write or append to file\0", 24);
               } else if (!strncmp(sys, "setxattr", 8)) {
					havecef = i;
					strncpy(msgname, "ATTR\0", 5);
					strncpy(msgdesc, "Change file attributes\0", 23);
				} else if (!strncmp(sys, "chmod", 5)) {
					havecef = i;
					strncpy(msgname, "CHMOD\0", 6);
					strncpy(msgdesc, "CHMOD failed\0", 13);
				} else if (!strncmp(sys, "chown", 5)) {
					havecef = i;
					strncpy(msgname, "CHOWN\0", 7);
					strncpy(msgdesc, "CHOWN failed\0", 13);
				} else if (!strncmp(sys, "ptrace",  6)) {
					havecef = i;
					strncpy(msgname, "PTRACE\0", 8);
					strncpy(msgdesc, "PTRACE called\0", 14);
				} else if (!strncmp(sys, "execve", 6)) {
                   havecef = i;
	    			strncpy(msgname, "EXECVE\0", 7);
		    		strncpy(msgdesc, "Unix Exec\0", 10);
               } else {
                   syslog(LOG_INFO, "Unhandled system call %u %s", i, sys);
               }

				key = auparse_find_field(au, "key");
				if (key)
					key = auparse_interpret_field(au);
				goto_record_type(au, type);
				ppid = auparse_find_field(au, "ppid");
				if (ppid) {
					i = auparse_get_field_int(au);
					snprintf(ppid_p, 1024, "/proc/%d/status", i);
					fp = fopen(ppid_p, "r");
					if (fp) {
						fscanf(fp, "Name: %255s", sppid);
						fclose(fp);
					}
				}

				goto_record_type(au, type);
				pid = auparse_find_field(au, "pid");
				goto_record_type(au, type);
				auid = auparse_find_field(au, "auid");
				if (auid) {
					i = auparse_get_field_int(au);
					if (i != -1)
						getpwuid_r(i, &pwd, buf, bufsize, &result);
				}
				goto_record_type(au, type);

				uid = auparse_find_field(au, "uid");
				if (uid && i == -1) {
					i = auparse_get_field_int(au);
					if (i != -1)
						getpwuid_r(i, &pwd, buf, bufsize, &result);
				}
				goto_record_type(au, type);

				tty = auparse_find_field(au, "tty");
				if (tty)
					tty = auparse_interpret_field(au);
				goto_record_type(au, type);

				gid = auparse_find_field(au, "gid");
				goto_record_type(au, type);
				euid = auparse_find_field(au, "euid");
				goto_record_type(au, type);
				suid = auparse_find_field(au, "suid");
				goto_record_type(au, type);
				fsuid = auparse_find_field(au, "fsuid");
				goto_record_type(au, type);
				egid = auparse_find_field(au, "egid");
				goto_record_type(au, type);
				sgid = auparse_find_field(au, "sgid");
				goto_record_type(au, type);
				fsgid = auparse_find_field(au, "fsgid");
				goto_record_type(au, type);
				ses = auparse_find_field(au, "ses");
				goto_record_type(au, type);

				if (extralen == 0) {
					extralen += snprintf(extra+extralen, 1024, "gid\\=%s euid\\=%s suid\\=%s fsuid\\=%s egid\\=%s sgid\\=%s fsgid\\=%s ses\\=%s",
						gid, euid, suid, fsuid, egid, sgid, fsgid, ses);
				} else {
					extralen += snprintf(extra+extralen, 1024, " gid\\=%s euid\\=%s suid\\=%s fsuid\\=%s egid\\=%s sgid\\=%s fsgid\\=%s ses\\=%s",
						gid, euid, suid, fsuid, egid, sgid, fsgid, ses);
				}

				exe = auparse_find_field(au, "exe");
				if (exe)
					exe = auparse_interpret_field(au);
				break;
			default:
				break;
		}
		num++;
	}

	if (!havecef)
		return;

	if (strlen(extra) >= 1024) {
		extra[1024] = '\0';
		strncpy(extrat, "Yes\0", 4);
	}

	syslog(LOG_INFO, "CEF:0|Unix|auditd|1|%s|%s|3|end=%ld fname=%s dhost=%s suser=%s \
suid=%s dproc=%s msg=%s \
cn1Label=auid cn1=%s \
cs1Label=Command cs1=%s \
cs2Label=Truncated cs2=%s \
cs3Label=AuditKey cs3=%s \
cs4Label=TTY cs4=%s \
cs5Label=ParentProcess cs5=%s \
cs6Label=MsgTruncated cs6=%s\n",
		msgname, msgdesc, au_time,
		fname, hostname, pwd.pw_name ? pwd.pw_name: NULL,
		uid, exe, extra, auid,
		fullcmd, fullcmdt,
		key, tty,
		sppid, extrat);
}
