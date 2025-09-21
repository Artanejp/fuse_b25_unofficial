/*
 * FUSE b25: MULTI2 de-scrambler for /dev/dvb/adapterN
 * Copyright 2011 0p1pp1
 * 
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include <config.h>

#include "using_fuse_version.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <fuse_opt.h>

#if FUSE_USE_VERSION >= 30
#include <fuse_lowlevel.h>
#endif

#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "fuse_b25_common.h"

#include "bcas.h"
#include "stream.h"
#include "secfilter.h"


struct options b25_priv;

enum {
	KEY_MY_USAGE = 0,
};

static struct fuse_opt b25_opts[] =
{
	{"--target %s", offsetof(struct options, target), 0},
	{"--card %s", offsetof(struct options, card_name), 0},
	{"--noemm", offsetof(struct options, emm), 0},
	{"--conv", offsetof(struct options, conv), 1},
	{"--eit", offsetof(struct options, eit), 1},
	{"--utc", offsetof(struct options, utc), 1},
	{"--cutoff", offsetof(struct options, cutoff), 1},
	{"--dmxraw", offsetof(struct options, dmxraw), 1},
	{"--maxthreads=%u", offsetof(struct options, max_threads), 1},
	{"--idlethreads=%u", offsetof(struct options, idle_threads), 2},
	{"--clonefd=%d", offsetof(struct options, clone_fd), 0},
	{"--logmask=%d", offsetof(struct options, log_mask), LOG_UPTO(LOG_DEBUG) & ~LOG_MASK(LOG_DEBUG)},
	FUSE_OPT_KEY("-h", KEY_MY_USAGE),
	FUSE_OPT_KEY("--help", KEY_MY_USAGE),

	FUSE_OPT_END
};

static void
my_usage(const char *prog_name)
{
	char *p = strdup(prog_name);

	fprintf(stderr,
		"%s specific options:\n"
		"    --target PATH\tuse PATH as the actual/original DVB adapter device\n"
		"                \t    (default: guessed from the mount point).\n"
		"    --card NAME  \tuse the BCAS card with the name NAME in PC/SC.\n"
		"    --noemm      \tdon't process EMM\n"
		"    --conv       \tconvert the text in NIT and SDT into UTF-16BE\n"
		"    --eit        \tconvert the text in EIT into UTF-16BE\n"
		"    --utc        \tconvert the time in EIT into UTC\n"
		"    --cutoff     \thold the output of the leading non-scrambled packtes\n"
		"                \t    until descrambling gets started\n"
		"    --dmxraw     \tdisable text conversion of the output from demuxN\n"
		"    --logmask value  \tSet logging masks as integer value ('1' bit is enabled.-1 = ALL ENABLED?).Default is upper-equal than LOG_INFO.\n"
		"\n", basename(p));
	free(p);
}

static void
set_target_path(char *dst, size_t len, const char *name)
{
	if (len == 0)
		return;

	strncpy(dst, b25_priv.target_dir, len);
	dst[len - 1] = '\0';
	strncat(dst, name, len - strlen(dst));
	dst[len - 1] = '\0';
}

/* file system operations */
#if FUSE_USE_VERSION < 30
static int
b25_getattr(const char *path, struct stat *stbuf)
#else
static int
b25_getattr(const char *path, struct stat *stbuf, UNUSED_VAR struct fuse_file_info *finfo)
#endif
{
	char target_path[64];
	if (fuse_interrupted())
		return -EINTR;
	
	set_target_path(target_path, sizeof(target_path), path);
	if (strcmp(path, "/") &&
	    strncmp(path, "/frontend", strlen("/frontend")) &&
	    strncmp(path, "/demux", strlen("/demux")) &&
	    strncmp(path, "/dvr", strlen("/dvr")))
		return -ENOENT;

	if (stat(target_path, stbuf))
		return -errno;

	/* need to cheat FUSE into recognizing it as a regular file */
	if (strcmp(path, "/")) {
		stbuf->st_mode &= ~S_IFCHR;
		stbuf->st_mode |= S_IFREG;
	}
	if (!strncmp(path, "/frontend", strlen("/frontend"))) {
		stbuf->st_mode &= ~S_IFREG;
		stbuf->st_mode |= S_IFLNK;
		stbuf->st_nlink = 1;
	}
	return 0;
}

static int
b25_readlink(const char *path, char *buf, size_t size)
{
	if (strncmp(path, "/frontend", strlen("/frontend")))
		return -EINVAL;
	set_target_path(buf, size, path);
	return 0;
}

/*
 * ToDo: flags set with FUSE_READDIR_PLUS .
 */
#if FUSE_USE_VERSION < 30
static int
b25_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
#else
static int
b25_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
#endif	
{
	DIR *d;
	struct dirent *ent;

	(void) offset;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	d = opendir(b25_priv.target_dir);
	if (!d)
		return -errno;

	while ((ent = readdir(d))) {
		/* contains just frontendX, demuxY, dvrZ */
		if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..") &&
		    strncmp(ent->d_name, "demux", strlen("demux")) &&
	    	    strncmp(ent->d_name, "dvr", strlen("dvr")) &&
		    strncmp(ent->d_name, "frontend", strlen("frontend"))) {
			continue;
		}
		#if FUSE_USE_VERSION < 30
		filler(buf, ent->d_name, NULL, 0);
		#else
		filler(buf, ent->d_name, NULL, 0, FUSE_FILL_DIR_PLUS | FUSE_READDIR_PLUS);
		#endif
	}

	closedir(d);
	return 0;
}

static int
b25_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	struct stream_priv *stream;
	struct secfilter_priv *filter;
	int res;
	char target_path[64];

	if (fuse_interrupted())
		return -EINTR;

	/*
	 * FIXME: if vfs layer does not check the permission,
	 * check here with fuse_get_context()->uid,gid
	 */

	SYSLOG_B25(LOG_DEBUG, "%s open flags:%#x\n", path, fi->flags);

	set_target_path(target_path, sizeof(target_path), path);
	fd = open(target_path, fi->flags | O_NONBLOCK);
	//fd = open(target_path, fi->flags );
	if (fd < 0) {
		res = -errno;
		SYSLOG_B25(LOG_INFO, "failed to open %s device: %m\n", path);
		return res;
	}

	fi->direct_io = 1;
	fi->nonseekable = 1;

	if (!strncmp(path, "/demux", strlen("/demux"))) {
		/* path: demuxN */
		filter = calloc(1, sizeof(struct secfilter_priv));
		if (filter == NULL) {
			SYSLOG_B25(LOG_NOTICE, "failed to allocate mem for sec.filter.\n");
			return -ENOMEM;
		}

		filter->fd = fd;
		filter->fs_priv = &b25_priv;
		if (init_secfilter(filter) != 0) {
			close(filter->fd);
			free(filter);
			return -ENXIO;
		}

		fi->fh = (int64_t)filter;
		return 0;
	}

	/* path: dvrN */

	stream = calloc(1, sizeof(struct stream_priv));
	if (stream == NULL) {
		SYSLOG_B25(LOG_NOTICE, "failed to allocate mem for stream.\n");
		return -ENOMEM;
	}

	stream->fd = fd;
	stream->fs_priv = &b25_priv;
	if (sscanf(path, "/dvr%u", &stream->dvr_no) != 1 ||
	    init_stream(stream) != 0) {
		close(stream->fd);
		free(stream);
		return -ENXIO;
	}

	fi->fh = (int64_t)stream;
	return 0;
}

static int
b25_release(const char *path, struct fuse_file_info *fi)
{
	struct secfilter_priv *filter;
	struct stream_priv *stream;

	if (!strncmp(path, "/demux", strlen("/demux"))) {
		filter = (struct secfilter_priv *)fi->fh;
		release_secfilter(filter);
		close(filter->fd);
		free(filter);
		return 0;
	}
	stream = (struct stream_priv *)fi->fh;
	release_stream(stream);
	close(stream->fd);
	free(stream);
	return 0;
}

static int
demux_read(const char *path, char *buf, size_t size, struct fuse_file_info *fi)
{
	struct secfilter_priv *filter;
	struct timeval now;
	struct timespec timeout;
	int len;
	int ret;
	unsigned int seclen;

	filter = (struct secfilter_priv *)fi->fh;
	pthread_mutex_lock(&filter->filter_lock);
	if (size == 0) {
		len = 0;
		goto done;
	}
	if (filter->err != 0) {
		len = -filter->err;
		filter->remaining_len = 0;
		SYSLOG_B25(LOG_DEBUG, "%s: LINE %d: failed to read from %s device. err:%d\n",
			__FUNCTION__, __LINE__, path, filter->err);
		goto done;
	} else if (filter->remaining_len > 0 &&
		   filter->stype != SECTION_TYPE_PES) {
		if (size > filter->remaining_len)
			size = filter->remaining_len;
		memcpy(buf, filter->remaining_buf, size);
		filter->remaining_len -= size;
		if (filter->remaining_len > 0)
			memmove(filter->remaining_buf,
				&filter->remaining_buf[size],
				filter->remaining_len);
		len = size;
		goto done;
	}

	while (filter->err == 0 &&
	       filter->outbuf_head == filter->outbuf_tail) {
		if (fi->flags & O_NONBLOCK || fi->flags & O_NDELAY) {
			pthread_mutex_unlock(&filter->filter_lock);
			return -EAGAIN;
		}

		gettimeofday(&now, NULL);
		timeout.tv_sec = now.tv_sec + 5;
		timeout.tv_nsec = now.tv_usec * 1000;
		ret = pthread_cond_timedwait(&filter->buf_cond,
					   &filter->filter_lock, &timeout);
		if (ret == EINTR || fuse_interrupted()) {
			pthread_mutex_unlock(&filter->filter_lock);
			return -EINTR;
		}
	}

	if (filter->err != 0) {
		len = -filter->err;
		filter->remaining_len = 0;
		SYSLOG_B25(LOG_DEBUG, "%s: LINE %d: failed to read from %s device. err:%d\n",
			__FUNCTION__, __LINE__, path, filter->err);
		goto done;
	}

	/* read out a whole section at once if possible */
	if (filter->stype != SECTION_TYPE_PES) {
		seclen = get_seclen(filter->outbuf_head, filter->outbuf,
			sizeof(filter->outbuf));
		if (size > seclen)
			size = seclen;
	} else {
		seclen = 0;
	}

	if (filter->outbuf_head > filter->outbuf_tail) {
		len = sizeof(filter->outbuf) - filter->outbuf_head;
		if (size < len)
			len = size;
		memcpy(buf, filter->outbuf + filter->outbuf_head, len);
		size -= len;
		filter->outbuf_head += len;
		if (filter->outbuf_head == sizeof(filter->outbuf))
			filter->outbuf_head = 0;
		if (size > 0) {
			if (size > filter->outbuf_tail)
				size = filter->outbuf_tail;
			memcpy(buf + len, filter->outbuf, size);
			filter->outbuf_head = size;
			len += size;
		}
	} else {
		len = filter->outbuf_tail - filter->outbuf_head;
		if (size < len)
			len = size;
		memcpy(buf, filter->outbuf + filter->outbuf_head, len);
		filter->outbuf_head += len;
	}

	if (filter->stype != SECTION_TYPE_PES && len < seclen) {
		int l;
		size = filter->remaining_len = seclen - len;
		buf = (char *)filter->remaining_buf;

		/* pop_secbuf remaining section data */
		if (filter->outbuf_head > filter->outbuf_tail) {
			l = sizeof(filter->outbuf) - filter->outbuf_head;
			if (size < l)
				l = size;
			memcpy(buf, filter->outbuf + filter->outbuf_head, l);
			size -= l;
			filter->outbuf_head += l;
			if (filter->outbuf_head == sizeof(filter->outbuf))
				filter->outbuf_head = 0;
			if (size > 0) {
				if (size > filter->outbuf_tail)
					size = filter->outbuf_tail;
				memcpy(buf + l, filter->outbuf, size);
				filter->outbuf_head = size;
				l += size;
			}
		} else {
			l = filter->outbuf_tail - filter->outbuf_head;
			if (size < l)
				l = size;
			memcpy(buf, filter->outbuf + filter->outbuf_head, l);
			filter->outbuf_head += l;
		}
		if (l != filter->remaining_len) {
			SYSLOG_B25(LOG_INFO, "broken buffer data detected.\n");
			filter->remaining_len = 0;
		}
	}

done:
	pthread_mutex_unlock(&filter->filter_lock);
	SYSLOG_B25(LOG_DEBUG, "read %d bytes from %s\n", len, path);
	return len;
}


static int
dvr_read(const char *path, char *buf, size_t size, struct fuse_file_info *fi)
{
	struct stream_priv *stream;
	struct timeval now;
	struct timespec timeout;
	int len;
	int ret;

	stream = (struct stream_priv *)fi->fh;
	pthread_mutex_lock(&stream->buf_lock);
	while (stream->err == 0 &&
	       stream->outbuf_head == stream->outbuf_tail) {
		if (fi->flags & O_NONBLOCK || fi->flags & O_NDELAY) {
			pthread_mutex_unlock(&stream->buf_lock);
			return -EAGAIN;
		}

		gettimeofday(&now, NULL);
		timeout.tv_sec = now.tv_sec + 5;
		timeout.tv_nsec = now.tv_usec * 1000;
		ret = pthread_cond_timedwait(&stream->buf_cond,
					   &stream->buf_lock, &timeout);
		if (ret == EINTR || fuse_interrupted()) {
			pthread_mutex_unlock(&stream->buf_lock);
			return -EINTR;
		}
	}

	if (stream->err != 0) {
		len = -stream->err;
		SYSLOG_B25(LOG_DEBUG, "%s: LINE %d: failed to read from %s device. err:%d\n",
			   __FUNCTION__, __LINE__, path, stream->err);
		goto done;
	}

	if (stream->outbuf_head > stream->outbuf_tail) {
		len = sizeof(stream->outbuf) - stream->outbuf_head;
		if (size < len)
			len = size;
		memcpy(buf, stream->outbuf + stream->outbuf_head, len);
		size -= len;
		stream->outbuf_head += len;
		if (stream->outbuf_head == sizeof(stream->outbuf))
			stream->outbuf_head = 0;
		if (size > 0) {
			if (size > stream->outbuf_tail)
				size = stream->outbuf_tail;
			memcpy(buf + len, stream->outbuf, size);
			stream->outbuf_head = size;
			len += size;
		}
	} else {
		len = stream->outbuf_tail - stream->outbuf_head;
		if (size < len)
			len = size;
		memcpy(buf, stream->outbuf + stream->outbuf_head, len);
		stream->outbuf_head += len;
	}

done:
	pthread_mutex_unlock(&stream->buf_lock);
	return len;
}

static int
b25_read(const char *path, char *buf, size_t size, off_t offset,
	 struct fuse_file_info *fi)
{
	(void)offset;

	if (fuse_interrupted())
		return -EINTR;

	if (!strncmp(path, "/demux", strlen("/demux")))
		return demux_read(path, buf, size, fi);
	else if (!strncmp(path, "/dvr", strlen("/dvr")))
		return dvr_read(path, buf, size, fi);

	return -EINVAL;
}


static int
b25_ioctl(const char *path, int cmd, void *arg,
	  struct fuse_file_info *fi, unsigned int flags, void *data)
{
	int fd;

	if (fuse_interrupted())
		return -EINTR;

	SYSLOG_B25(LOG_DEBUG, "ioctl on %s cmd:%x arg:%p\n", path, cmd, arg);

#if 0
	if (flags & FUSE_IOCTL_COMPAT)
		return -ENOSYS;
#endif

	if (!strncmp(path, "/demux", strlen("/demux"))) {
		struct secfilter_priv *priv;

		priv = (struct secfilter_priv *)fi->fh;
		fd = priv->fd;
		secfilter_ioctl_hook(priv, cmd, data);
	} else if (!strncmp(path, "/dvr", strlen("/dvr")))
		fd = ((struct stream_priv *)fi->fh)->fd;
	else
		return -ENOTTY;

	if (ioctl(fd, cmd, data))
		return -errno;

	return 0;
}

static int
demux_poll(const char *path, struct fuse_file_info *fi,
	 struct fuse_pollhandle *ph, unsigned *reventsp)
{
	struct secfilter_priv *filter;

	filter = (struct secfilter_priv *)fi->fh;

	*reventsp = 0;
	pthread_mutex_lock(&filter->filter_lock);
	if (ph != NULL) {
		if (filter->ph != NULL)
			fuse_pollhandle_destroy(filter->ph);
		filter->ph = ph;
	}

	if (filter->err != 0)
		*reventsp = POLLERR;
	else if (filter->outbuf_head != filter->outbuf_tail)
		*reventsp = POLLIN;

	pthread_mutex_unlock(&filter->filter_lock);
	return 0;
}

static int
dvr_poll(const char *path, struct fuse_file_info *fi,
	 struct fuse_pollhandle *ph, unsigned *reventsp)
{
	struct stream_priv *stream;

	stream = (struct stream_priv *)fi->fh;

	*reventsp = 0;
	pthread_mutex_lock(&stream->buf_lock);
	if (ph != NULL) {
		if (stream->ph != NULL)
			fuse_pollhandle_destroy(stream->ph);
		stream->ph = ph;
	}

	if (stream->err != 0)
		*reventsp = POLLERR;
	else if (stream->outbuf_head != stream->outbuf_tail)
		*reventsp = POLLIN;

	pthread_mutex_unlock(&stream->buf_lock);
	return 0;
}

static int
b25_poll(const char *path, struct fuse_file_info *fi,
	 struct fuse_pollhandle *ph, unsigned *reventsp)
{
	if (fuse_interrupted())
		return -EINTR;

	if (!strncmp(path, "/demux", strlen("/demux")))
		return demux_poll(path, fi, ph, reventsp);
	else if (!strncmp(path, "/dvr", strlen("/dvr")))
		return dvr_poll(path, fi, ph, reventsp);
	return -EBADF;
}

/*
 * ToDo: init with *cfg.
 */
#if FUSE_USE_VERSION < 30
static void *
b25_init(struct fuse_conn_info *conn)
#else
static void *
b25_init(struct fuse_conn_info *conn, UNUSED_VAR struct fuse_config *cfg)
#endif
{
	int res;

	(void)conn;

	b25_priv.card.iccname = b25_priv.card_name;
	res = bcas_init(&b25_priv.card);
	if (res != 0) {
		SYSLOG_B25(LOG_NOTICE, "failed to invoke the card I/O thread.\n");
		fuse_exit(fuse_get_context()->fuse);
		return NULL;
	}
	return &b25_priv.card;
}

static void
b25_destroy(void *priv)
{
	struct bcas *card;

	card = &b25_priv.card;
	if (card != NULL)
		bcas_destroy(card);
}

static struct fuse_operations b25_ops = {
	.getattr = b25_getattr,
	.readlink = b25_readlink,
	.readdir = b25_readdir,
	.open = b25_open,
	.release = b25_release,
	.read = b25_read,
	.ioctl = b25_ioctl,
	.poll = b25_poll,
	.init = b25_init,
	.destroy = b25_destroy,
};

static int
my_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	if (key == KEY_MY_USAGE)
		my_usage(outargs->argv[0]);
	return 1;
}

int
main(int argc, char **argv)
{
	struct fuse *fuse;
	char *mountpoint;
	int multithreaded;
	int res;
	unsigned int adapter;
	unsigned int t_adap;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct stat st;
	char dmx[64];

	openlog("FUSE_b25", LOG_PID | LOG_PERROR, LOG_LOCAL7);
	memset(&b25_priv, 0, sizeof(b25_priv));
	b25_priv.emm = 1;
	b25_priv.conv = 0;
	b25_priv.log_mask = LOG_UPTO(LOG_DEBUG) & ~LOG_MASK(LOG_DEBUG);
	res = fuse_opt_parse(&args, &b25_priv, b25_opts, &my_opt_proc);
	if (res == -1) {
		SYSLOG_B25(LOG_NOTICE, "failed to parse options: %m\n");
		return 1;
	}
	/* copied from fuse_main_real() */
	
	#if FUSE_USE_VERSION < 30
	res = fuse_opt_add_arg(&args, "-odirect_io");
	res += fuse_opt_add_arg(&args, "-odefault_permissions");
	if (res < 0) {
		SYSLOG_B25(LOG_NOTICE, "failed to add \"direct_io\"/"
			"\"default_permissions\" options: %m\n");
		return 1;
	}

	fuse = fuse_setup(args.argc, args.argv, &b25_ops, sizeof(b25_ops),
			  &mountpoint, &multithreaded, NULL);
	fuse_opt_free_args(&args);
	#else
	struct fuse_cmdline_opts cmd_ops;
	
	if(fuse_parse_cmdline(&args, &cmd_ops) != 0) {
		SYSLOG_B25(LOG_NOTICE, "extra arguments parse error.\n");
		return 1;
	}
	mountpoint = cmd_ops.mountpoint;
	multithreaded = (cmd_ops.singlethread == 0) ? 1 : 0;
	
	if(mountpoint == NULL) {
		SYSLOG_B25(LOG_NOTICE, "mountpoint not found\n");
		return 2;
	}
	fuse = fuse_new_session(&args, &b25_ops, sizeof(b25_ops), NULL);
	fuse_opt_free_args(&args);
	#endif
	
	if (fuse == NULL) {
		SYSLOG_B25(LOG_NOTICE, "failed to setup fuse.  options: %s\n", mountpoint);
		return 1;
	}
	res = sscanf(mountpoint, "/dev/dvb/adapter%u", &adapter);
	if (res != 1) {
		SYSLOG_B25(LOG_NOTICE, "invalid mount point: \"%s\"\n", mountpoint);
		#if FUSE_USE_VERSION >= 30
		fuse_destroy(fuse);
		#endif
		return 4;
	}
	#if FUSE_USE_VERSION >= 30
	if(fuse_mount(fuse, mountpoint) < 0) {
		SYSLOG_B25(LOG_NOTICE, "failed to mount point %s. BYE.\n");
		fuse_destroy(fuse);
		return 2;
	}
	#endif

	if (b25_priv.target) {
		res = readlink(b25_priv.target, b25_priv.target_dir,
			sizeof(b25_priv.target_dir));
		if (res == -1 && errno == EINVAL) {
			strncpy(b25_priv.target_dir, b25_priv.target, 
				sizeof(b25_priv.target_dir));
			b25_priv.target_dir[sizeof(b25_priv.target_dir) - 1] = '\x0';
			res = strlen(b25_priv.target_dir);
		}
		if (res >= 0 && res + 1 < sizeof(b25_priv.target_dir))
			b25_priv.target_dir[res] = '\x0';
		else
			b25_priv.target_dir[sizeof(b25_priv.target_dir) - 1] = '\x0';

		res = sscanf(b25_priv.target_dir, "/dev/dvb/adapter%u", &t_adap);
		if (res != 1 || t_adap == adapter)
			res = -1;
		else
			res = 0;
	} else {
		// default mapping: 
		// /dev/dvb/adapterN <- /dev/dvb/adapter(8+N)
		t_adap = adapter - 8;
		if (adapter >= 8) {
			res = snprintf(b25_priv.target_dir, sizeof(b25_priv.target_dir),
				       "/dev/dvb/adapter%u", t_adap);
			b25_priv.target_dir[sizeof(b25_priv.target_dir) - 1] = '\x0';
		} else
			res = -1;
	}
	SYSLOG_B25(LOG_INFO, "Try to open target DVB device path:[%s]\n", b25_priv.target_dir);

	set_target_path(dmx, sizeof(dmx), "/demux0");
	if (res < 0 || stat(dmx, &st) || !S_ISCHR(st.st_mode)
#ifdef HAVE_EACCESS
	   || eaccess(dmx, R_OK)
#endif
	   ) {
		SYSLOG_B25(LOG_NOTICE, "can't access the target DVB device:[%s/]\n", b25_priv.target_dir);
		#if FUSE_USE_VERSION >= 30
		fuse_unmount(fuse);
		fuse_destroy(fuse);
		#endif
		return 1;
	}
	/* set log mask */
        setlogmask(b25_priv.log_mask);

	/* main loop */
	#if FUSE_USE_VERSION < 30
	if (multithreaded)
		res = fuse_loop_mt(fuse);
	else
		res = fuse_loop(fuse);
	#else
	if (multithreaded) {
		#if FUSE_USE_VERSION < 32
		res = fuse_loop_mt(fuse, cmd_ops.clone_fd);
		#elif FUSE_USE_VERSION < FUSE_MAKE_VERSION(3, 12)
		struct fuse_loop_config lcfg;
		lcfg.clone_fd = (cmd_ops.clone_fd != 0) ? 1 : 0;
		lcfg.max_idle_threads = (cmd_ops.max_idle_threads == 0) ? 1 : cmd_ops.max_idle_threads;
		res = fuse_loop_mt(fuse, &lcfg);
		#else
		struct fuse_loop_config *plcfg = fuse_loop_cfg_create();
		if(plcfg == NULL) {
			res = fuse_loop(fuse);
		} else { // Created
			fuse_loop_cfg_set_clone_fd(plcfg, cmd_ops.clone_fd);
			fuse_loop_cfg_set_idle_threads(plcfg, (cmd_ops.max_idle_threads < 1) ? 1 : cmd_ops.max_idle_threads);
			if(cmd_ops.max_idle_threads < 1)
				cmd_ops.max_idle_threads = 1;
			
			fuse_loop_cfg_set_max_threads(plcfg, (cmd_ops.max_threads <= cmd_ops.max_idle_threads) ? (cmd_ops.max_idle_threads + 1) : cmd_ops.max_threads); 
			res = fuse_loop_mt(fuse, pcfg);
			fuse_loop_cfg_destroy(pcfg);
		}
		#endif
	} else {
		res = fuse_loop(fuse);
	}
	#endif
	if (res == -1)
		SYSLOG_B25(LOG_NOTICE, "failed in fuse_loop: %m\n");

	#if FUSE_USE_VERSION < 30
	fuse_teardown(fuse, mountpoint);
	#else
	fuse_unmount(fuse);
	fuse_destroy(fuse);
	#endif
	closelog();
	return res;
}
