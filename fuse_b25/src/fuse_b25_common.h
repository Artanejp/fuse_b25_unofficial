/*
 * fuse_b25_common.h: common macros.
 * Copyright 2022 K.O
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _FUSE_B25_COMMON_H_
#define _FUSE_B25_COMMON_H_

#ifdef NO_SYSLOG
#define syslog(a, args...) fprintf(stderr, args...)
#endif

#define SYSLOG_B25(sev, fmt, ...)										\
	syslog(sev, "%s() in file %s, line %d: "fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)

//#define SYSLOG_B25(sev, fmt, ...) 

#ifndef UNUSED_VAR
	#ifdef __GNUC__
	#define UNUSED_VAR __attribute__((unused))
	#else
	#define UNUSED_VAR
	#endif
#endif

#endif /* _FUSE_B25_COMMON_H_ */
