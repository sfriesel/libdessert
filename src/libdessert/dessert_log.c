/******************************************************************************
 Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).
 All rights reserved.

 These sources were originally developed by Philipp Schmidt
 at Freie Universitaet Berlin (http://www.fu-berlin.de/),
 Computer Systems and Telematics / Distributed, Embedded Systems (DES) group
 (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)
 ------------------------------------------------------------------------------
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program. If not, see http://www.gnu.org/licenses/ .
 ------------------------------------------------------------------------------
 For further information and questions please use the web site
 http://www.des-testbed.net/
 *******************************************************************************/

#include "dessert_internal.h"
#include "dessert.h"
#include <sys/stat.h>
#include <signal.h>

#ifdef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <config.h>
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

/* data storage */
FILE *dessert_logfd = NULL;
#ifdef HAVE_LIBZ
gzFile *dessert_logfdgz = NULL;
#endif

char dessert_logprefix[12];

#define _DESSERT_LOGFLAG_SYSLOG   0x01
#define _DESSERT_LOGFLAG_LOGFILE  0x02
#define _DESSERT_LOGFLAG_STDERR   0x04
#define _DESSERT_LOGFLAG_RBUF     0x08
#define _DESSERT_LOGFLAG_GZ       0x10

int _dessert_logflags = _DESSERT_LOGFLAG_STDERR;
int _dessert_loglevel = LOG_INFO;

/* the logging ringbuffer */
char *_dessert_logrbuf = NULL; /* pointer to begin */
int _dessert_logrbuf_len = 0; /* length in lines (DESSERT_LOGLINE_MAX*_dessert_logrbuf_len*sizeof(char) would be in bytes) */
int _dessert_logrbuf_cur = 0; /* current position */
int _dessert_logrbuf_used = 0; /* used slots */
pthread_rwlock_t _dessert_logrbuf_len_lock = PTHREAD_RWLOCK_INITIALIZER; /* for resizing */
pthread_mutex_t _dessert_logrbuf_mutex = PTHREAD_MUTEX_INITIALIZER; /* for moving _dessert_logrbuf_cur */
pthread_mutex_t _dessert_logfile_mutex = PTHREAD_MUTEX_INITIALIZER;

/* internal functions forward declarations \todo cleanup */

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * L O G   F A C I L I T Y
 *
 ******************************************************************************/

/** Configure dessert logging framework and sets up logging.
 *
 * @arg opts OR'd flags - @see DESSERT_LOG_*
 *
 * %DESCRIPTION:
 *
 **/
int dessert_logcfg(uint16_t opts) {
	snprintf(dessert_logprefix, 12, "dessert/%s", dessert_proto);

	pthread_rwlock_wrlock(&dessert_cfglock);

	/* configure logging */
	if ((opts & DESSERT_LOG_SYSLOG) && !(opts & DESSERT_LOG_NOSYSLOG)) {
		if (!(_dessert_logflags & _DESSERT_LOGFLAG_SYSLOG)) {
			/* initialize syslog channel */
			openlog(dessert_logprefix, LOG_PID, LOG_DAEMON);
		}
		_dessert_logflags |= _DESSERT_LOGFLAG_SYSLOG;
	} else if (!(opts & DESSERT_LOG_SYSLOG) && (opts & DESSERT_LOG_NOSYSLOG)) {
		if (_dessert_logflags & _DESSERT_LOGFLAG_SYSLOG) {
			/* close syslog channel */
			closelog();
		}
		_dessert_logflags &= ~_DESSERT_LOGFLAG_SYSLOG;
	}

	if ((opts & DESSERT_LOG_STDERR) && !(opts & DESSERT_LOG_NOSTDERR)
			&& !(_dessert_status & _DESSERT_STATUS_DAEMON)) {
		_dessert_logflags |= _DESSERT_LOGFLAG_STDERR;
	} else if ((!(opts & DESSERT_LOG_STDERR) && (opts & DESSERT_LOG_NOSTDERR))
			|| (_dessert_status & _DESSERT_STATUS_DAEMON)) {
		_dessert_logflags &= ~_DESSERT_LOGFLAG_STDERR;
	}

#ifdef HAVE_LIBZ
    // enable or disable compression
    if((opts & DESSERT_LOG_GZ) && !(opts & DESSERT_LOG_NOGZ)) {
      _dessert_logflags |= _DESSERT_LOGFLAG_GZ;
    }
    else if((!(opts & DESSERT_LOG_GZ) && (opts & DESSERT_LOG_NOGZ))) {
      _dessert_logflags &= ~_DESSERT_LOGFLAG_GZ;
    }
#endif

	if ((opts & DESSERT_LOG_FILE) && !(opts & DESSERT_LOG_NOFILE)
			&& (dessert_logfd != NULL
#ifdef HAVE_LIBZ
			|| dessert_logfdgz != NULL
#endif
			)) {
		_dessert_logflags |= _DESSERT_LOGFLAG_LOGFILE;
	} else if ((!(opts & DESSERT_LOG_FILE) && (opts & DESSERT_LOG_NOFILE))
			|| (dessert_logfd == NULL
#ifdef HAVE_LIBZ
			&& dessert_logfdgz == NULL
#endif
			)) {
		_dessert_logflags &= ~_DESSERT_LOGFLAG_LOGFILE;
	}

	if ((opts & DESSERT_LOG_RBUF) && !(opts & DESSERT_LOG_NORBUF)) {
		_dessert_logflags |= _DESSERT_LOGFLAG_RBUF;
	} else if (!(opts & DESSERT_LOG_RBUF) && (opts & DESSERT_LOG_NORBUF)) {
		_dessert_logflags &= ~_DESSERT_LOGFLAG_RBUF;
	}

	pthread_rwlock_unlock(&dessert_cfglock);

	return 0;
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * L O G   F A C I L I T Y
 *
 ******************************************************************************/

char* _dessert_log_rbuf_nextline(void) {
	char* r = NULL;
	pthread_mutex_lock(&_dessert_logrbuf_mutex);
	if (_dessert_logrbuf_len > 0) {
		if (_dessert_logrbuf_cur >= _dessert_logrbuf_len) {
			_dessert_logrbuf_cur = 0;
		}
		r = _dessert_logrbuf + (DESSERT_LOGLINE_MAX * _dessert_logrbuf_cur);
		_dessert_logrbuf_cur++;
		if (_dessert_logrbuf_used < _dessert_logrbuf_len - 1) {
			_dessert_logrbuf_used++;
		}
	}
	pthread_mutex_unlock(&_dessert_logrbuf_mutex);

	return (r);
}

/** internal log function
 *
 * @internal
 *
 * @param[in] level loglevel from <syslog.h>
 * @param[in] *func function name called from
 * @param[in] *file file name called from
 * @param[in] *line line called from
 * @param[in] *fmt printf format string
 * @param[in] ... (var-arg) printf like variables
 **/
void _dessert_log(int level, const char* func, const char* file, int line,
		const char *fmt, ...) {
	va_list args;
	char *rbuf_line = NULL;
	char buf[DESSERT_LOGLINE_MAX];
	char lf[80];
	char *lt;
	char lds[27];
	struct tm ldd;
	time_t ldi;
	int lf_slen, buf_slen;

	if (_dessert_loglevel < level)
		return;

	snprintf(lf, 80, " (%s@%s:%d)", func, file, line);
	lf_slen = strlen(lf);

	va_start(args, fmt);
	vsnprintf(buf, DESSERT_LOGLINE_MAX, fmt, args);
	va_end(args);
	buf_slen = strlen(buf);

	if (_dessert_logflags & _DESSERT_LOGFLAG_SYSLOG) {
		syslog(level, "%s%s", buf, lf);
	}

	if (_dessert_logflags & _DESSERT_LOGFLAG_RBUF) {
		pthread_rwlock_rdlock(&_dessert_logrbuf_len_lock);
		rbuf_line = _dessert_log_rbuf_nextline();
	}

	if (_dessert_logflags & (_DESSERT_LOGFLAG_LOGFILE | _DESSERT_LOGFLAG_STDERR
			| _DESSERT_LOGFLAG_RBUF)) {

		time(&ldi);
		localtime_r(&ldi, &ldd);
		snprintf(lds, 26, "%04d-%02d-%02d %02d:%02d:%02d%+05.1f ", ldd.tm_year
				+ 1900, ldd.tm_mon + 1, ldd.tm_mday, ldd.tm_hour, ldd.tm_min,
				ldd.tm_sec, (double) ldd.tm_gmtoff / 3600);

        switch (level) {
          case LOG_EMERG:
              lt = "EMERG: ";
              break;
          case LOG_ALERT:
              lt = "ALERT: ";
              break;
          case LOG_CRIT:
              lt = "CRIT:  ";
              break;
          case LOG_ERR:
              lt = "ERR:   ";
              break;
          case LOG_WARNING:
              lt = "WARN:  ";
              break;
          case LOG_NOTICE:
              lt = "NOTICE:";
              break;
          case LOG_INFO:
              lt = "INFO:  ";
              break;
          default:
              lt = "DEBUG: ";
              break;
        }

// 		if (32 + buf_slen + lf_slen > 80) {
            if (_dessert_logflags & _DESSERT_LOGFLAG_LOGFILE) {
              pthread_mutex_lock(&_dessert_logfile_mutex);
              if(dessert_logfd != NULL) {
                fprintf(dessert_logfd, "%s%s%s\n%80s\n", lds, lt, buf, lf);
              }
#ifdef HAVE_LIBZ
              else if(dessert_logfdgz != NULL) {
                gzprintf(dessert_logfdgz, "%s%s%s\n%80s\n", lds, lt, buf, lf);
              }
#endif
              pthread_mutex_unlock(&_dessert_logfile_mutex);
            }
            if (_dessert_logflags & _DESSERT_LOGFLAG_STDERR)
                fprintf(stderr, "%s%s%s\n%80s\n", lds, lt, buf, lf);
            if (_dessert_logflags & _DESSERT_LOGFLAG_RBUF && rbuf_line != NULL)
                snprintf(rbuf_line, DESSERT_LOGLINE_MAX, "%s%s%s\n%80s", lds,
                        lt, buf, lf);
// 		} else {
// 			while (32 + buf_slen + lf_slen < 80) {
// 				buf[buf_slen++] = ' ';
// 			}
// 			buf[buf_slen] = '\0';
// 			if (_dessert_logflags & _DESSERT_LOGFLAG_LOGFILE) {
//               if(dessert_logfd != NULL)
// 				fprintf(dessert_logfd, "%s%s%s%s\n", lds, lt, buf, lf);
// #ifdef HAVE_LIBZ
//               else if(dessert_logfdgz != NULL)
//                 gzprintf(dessert_logfdgz, "%s%s%s%s\n", lds, lt, buf, lf);
// #endif
//             }
// 			if (_dessert_logflags & _DESSERT_LOGFLAG_STDERR)
// 				fprintf(stderr, "%s%s%s%s\n", lds, lt, buf, lf);
// 			if (_dessert_logflags & _DESSERT_LOGFLAG_RBUF && rbuf_line != NULL)
// 				snprintf(rbuf_line, DESSERT_LOGLINE_MAX, "%s%s%s%s", lds, lt,
// 						buf, lf);
// 		}

		if (_dessert_logflags & _DESSERT_LOGFLAG_LOGFILE) {
          if(dessert_logfd != NULL)
			fflush(dessert_logfd);
#ifdef HAVE_LIBZ
          else if(dessert_logfdgz != NULL)
            gzflush(dessert_logfdgz, Z_FULL_FLUSH);
#endif
		}
		if (_dessert_logflags & _DESSERT_LOGFLAG_RBUF) {
			pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
		}

	}
}

/** command "logging file" */
int _dessert_cli_logging_file(struct cli_def *cli, char *command, char *argv[],
		int argc) {
	FILE *newlogdf = NULL;
#ifdef HAVE_LIBZ
    gzFile *newlogdfgz = NULL;
    const char gz[] = ".gz";
#endif

	if (argc != 1) {
		cli_print(cli, "usage %s filename\n", command);
		return CLI_ERROR;
	}

#ifdef HAVE_LIBZ
    // see if the filename ends with ".gz"
    int len = strlen(argv[0]);
    int wrong_fext = strcmp(gz, argv[0]+len+1-sizeof(gz));

    /* enable compression if the deamon author set the corresponding flag
       or the filename ends on ".gz" */
    if((_dessert_logflags & _DESSERT_LOGFLAG_GZ)
      || !wrong_fext) {
      if(wrong_fext) {
        char newname[len+sizeof(gz)+1];
        snprintf(newname, len+sizeof(gz)+1, "%s%s", argv[0], gz);
        newlogdfgz = gzopen(newname, "a");
      }
      else {
        newlogdfgz = gzopen(argv[0], "a");
      }
    }
    else
#endif
    {
      newlogdf = fopen(argv[0], "a");
    }

	if (newlogdf == NULL
#ifdef HAVE_LIBZ
      && newlogdfgz == NULL
#endif
      ) {
		dessert_err("failed o open %s as logfile\n", argv[0]);
		cli_print(cli, "failed o open %s as logfile\n", argv[0]);
		return CLI_ERROR;
	}

	/* clean up old logfile first */
	if (dessert_logfd != NULL) {
		dessert_logcfg(DESSERT_LOG_NOFILE);
		fclose(dessert_logfd);
	}
#ifdef HAVE_LIBZ
	if (dessert_logfdgz != NULL) {
        dessert_logcfg(DESSERT_LOG_NOFILE);
        gzclose(dessert_logfdgz);
    }
#endif

    if(newlogdf) {
      dessert_logfd = newlogdf;
      dessert_logcfg(DESSERT_LOG_FILE | DESSERT_LOG_NOGZ);
    }
#ifdef HAVE_LIBZ
    if(newlogdfgz) {
      dessert_logfdgz = newlogdfgz;
      dessert_logcfg(DESSERT_LOG_FILE | DESSERT_LOG_GZ);
    }
#endif

	return CLI_OK;
}

int _dessert_closeLogFile(int signal) {
    dessert_notice("closing log file");
    dessert_logcfg(DESSERT_LOG_NOFILE);
    if (dessert_logfd != NULL) {
        fclose(dessert_logfd);
    }
    dessert_logfd = NULL;

#ifdef HAVE_LIBZ
    if (dessert_logfdgz != NULL) {
        gzclose(dessert_logfdgz);
    }
    dessert_logfdgz = NULL;
#endif
  return 0;
}

int _dessert_log_init() {
  dessert_signalcb_add(SIGTERM, _dessert_closeLogFile);
  return 0;
}

/** command "no logging file" */
int _dessert_cli_no_logging_file(struct cli_def *cli, char *command, char *argv[], int argc) {
    _dessert_closeLogFile(0);
    return CLI_OK;
}

/** command "logging ringbuffer" */
int _dessert_cli_logging_ringbuffer(struct cli_def *cli, char *command,
		char *argv[], int argc) {
	int newlen = -1;
	if (argc != 1 || (newlen = (int) strtol(argv[0], NULL, 10)) < 0) {
		cli_print(cli, "usage %s [buffer length]\n", command);
		return CLI_ERROR;
	}

	if (newlen == _dessert_logrbuf_len)
		return CLI_OK;

	if (newlen == 0) {
		cli_print(cli,
				"will not set buffer length to 0 - use no logging ringbuffer instead\n");
		return CLI_ERROR;
	}

	pthread_rwlock_wrlock(&_dessert_logrbuf_len_lock);

	/* make logging buffer larger - easy if not ENOMEM*/
	if (newlen > _dessert_logrbuf_len) {
		_dessert_logrbuf = realloc(_dessert_logrbuf, newlen
				* DESSERT_LOGLINE_MAX * sizeof(char));
		if (_dessert_logrbuf == NULL) {
			_dessert_logrbuf_len = 0;
			_dessert_logrbuf_cur = 0;
		} else {
			_dessert_logrbuf_len = newlen;
		}
		dessert_logcfg(DESSERT_LOG_RBUF);
		/* make logging buffer smaller - pain in the ass */
	} else if (newlen < _dessert_logrbuf_len) {
		/* move current log buffer if needed */
		if (_dessert_logrbuf_cur > newlen) {
			memmove(_dessert_logrbuf, _dessert_logrbuf + (DESSERT_LOGLINE_MAX
					* (_dessert_logrbuf_cur - newlen)), newlen
					* DESSERT_LOGLINE_MAX * sizeof(char));
			_dessert_logrbuf_cur -= newlen;
		}
		_dessert_logrbuf = realloc(_dessert_logrbuf, newlen
				* DESSERT_LOGLINE_MAX * sizeof(char));
		if (_dessert_logrbuf == NULL) {
			_dessert_logrbuf_len = 0;
			_dessert_logrbuf_cur = 0;
		} else {
			_dessert_logrbuf_len = newlen;
		}
	} else {
		dessert_err("this never happens");
	}
	if (_dessert_logrbuf_used > _dessert_logrbuf_len - 1)
		_dessert_logrbuf_used = _dessert_logrbuf_len - 1;
	pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
	return CLI_OK;

}

/** command "no logging ringbuffer" */
int _dessert_cli_no_logging_ringbuffer(struct cli_def *cli, char *command,
		char *argv[], int argc) {
	if (_dessert_logrbuf == NULL) {
		return CLI_OK;
	} else {
		pthread_rwlock_wrlock(&_dessert_logrbuf_len_lock);
		dessert_logcfg(DESSERT_LOG_NORBUF);
		free(_dessert_logrbuf);
		_dessert_logrbuf = NULL;
		_dessert_logrbuf_len = 0;
		_dessert_logrbuf_cur = 0;
		pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
		return CLI_OK;
	}

}

/** just a helper function */
int _dessert_loglevel_to_string(uint8_t level, char* buffer, size_t len) {
    switch(level) {
        case LOG_DEBUG:
            snprintf(buffer, len, "%s", "debug");
            break;
        case LOG_INFO:
            snprintf(buffer, len, "%s", "info");
            break;
        case LOG_NOTICE:
            snprintf(buffer, len, "%s", "notice");
            break;
        case LOG_WARNING:
            snprintf(buffer, len, "%s", "warning");
            break;
        case LOG_ERR:
            snprintf(buffer, len, "%s", "error");
           break;
        case LOG_CRIT:
            snprintf(buffer, len, "%s", "critical");
            break;
        case LOG_EMERG:
            snprintf(buffer, len, "%s", "emergency");
            break;
        default:
            return -1;
    }
    return 0;
}

int _dessert_cli_cmd_set_loglevel(struct cli_def *cli, char *command, char *argv[],
        int argc) {
     if(argc != 1 ) {
        cli_print(cli, "usage %s [(d)ebug, (i)nfo, (n)otice, (w)arning, (e)rror, (c)ritical, e(m)ergency]", command);
        return CLI_ERROR;
    }

    switch(argv[0][0]) {
        case 'd':
        case 'D':
            _dessert_loglevel = LOG_DEBUG;
            break;
        case 'i':
        case 'I':
            _dessert_loglevel = LOG_INFO;
            break;
        case 'n':
        case 'N':
            _dessert_loglevel = LOG_NOTICE;
            break;
        case 'w':
        case 'W':
            _dessert_loglevel = LOG_WARNING;
            break;
        case 'e':
        case 'E':
            _dessert_loglevel = LOG_ERR;
            break;
        case 'c':
        case 'C':
            _dessert_loglevel = LOG_CRIT;
            break;
        case 'm':
        case 'M':
            _dessert_loglevel = LOG_EMERG;
            break;
        default:
            cli_print(cli, "invalid loglevel specified: %s", argv[0]);
            dessert_warn("invalid loglevel specified: %s", argv[0]);
    }
    char buf[20];
    _dessert_loglevel_to_string(_dessert_loglevel, buf, 20);
    cli_print(cli, "loglevel is set to \"%s\"", buf);
    dessert_notice("loglevel is set to \"%s\"", buf);
}

int _dessert_cli_cmd_show_loglevel(struct cli_def *cli, char *command, char *argv[], int argc) {
    char buf[20];
    _dessert_loglevel_to_string(_dessert_loglevel, buf, 20);
    cli_print(cli, "loglevel is set to \"%s\"", buf);
}

/** command "show logging" */
int _dessert_cli_cmd_logging(struct cli_def *cli, char *command, char *argv[],
		int argc) {
	pthread_rwlock_rdlock(&_dessert_logrbuf_len_lock);
	int i = 0;
	int max = _dessert_logrbuf_len - 1;
	char* line;

	if (_dessert_logrbuf_len < 1) {
		cli_print(
				cli,
				"logging to ringbuffer is disables - use \"logging ringbuffer [int]\" in config-mode first");
		pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
		return CLI_ERROR;
	}

	if (argc == 1) {
		int max2 = (int) strtol(argv[0], NULL, 10);
		if (max2 > 0) {
			max = max2;
		}
	}

	/* where to start and print? */
	if (max > _dessert_logrbuf_used) {
		max = _dessert_logrbuf_used;
	}
	i = _dessert_logrbuf_cur - max - 1;
	if (i < 0) {
		i += _dessert_logrbuf_len;
	}

	while (max > 0) {
		i++;
		max--;
		if (i == _dessert_logrbuf_len) {
			i = 0;
		}
		line = _dessert_logrbuf + (DESSERT_LOGLINE_MAX * i);
		cli_print(cli, "%s", line);
	}

	pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);

	return CLI_OK;
}
