/*
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* XXX: memleaks */
/* XXX: signed vs unsigned */
/* XXX: redesign to allow concurrent overlapped operations */
/* XXX: we use fatal too much, error may be more appropriate in places */
/* XXX: copy between two remote sites */

#include "includes.h"
RCSID("$OpenBSD: sftp-client.c,v 1.4 2001/02/06 23:30:28 djm Exp $");

#include "ssh.h"
#include "buffer.h"
#include "bufaux.h"
#include "getput.h"
#include "xmalloc.h"
#include "log.h"
#include "atomicio.h"
#include "pathnames.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"

/* How much data to read/write at at time during copies */
/* XXX: what should this be? */
#define COPY_SIZE	8192

/* Message ID */
static u_int msg_id = 1;

void
send_msg(int fd, Buffer *m)
{
	int mlen = buffer_len(m);
	int len;
	Buffer oqueue;

	buffer_init(&oqueue);
	buffer_put_int(&oqueue, mlen);
	buffer_append(&oqueue, buffer_ptr(m), mlen);
	buffer_consume(m, mlen);

	len = atomicio(write, fd, buffer_ptr(&oqueue), buffer_len(&oqueue));
	if (len <= 0)
		fatal("Couldn't send packet: %s", strerror(errno));

	buffer_free(&oqueue);
}

void
get_msg(int fd, Buffer *m)
{
	u_int len, msg_len;
	unsigned char buf[4096];

	len = atomicio(read, fd, buf, 4);
	if (len != 4)
		fatal("Couldn't read packet: %s", strerror(errno));

	msg_len = GET_32BIT(buf);
	if (msg_len > 256 * 1024)
		fatal("Received message too long %d", msg_len);

	while (msg_len) {
		len = atomicio(read, fd, buf, MIN(msg_len, sizeof(buf)));
		if (len <= 0)
			fatal("Couldn't read packet: %s", strerror(errno));

		msg_len -= len;
		buffer_append(m, buf, len);
	}
}

void
send_string_request(int fd, u_int id, u_int code, char *s,
    u_int len)
{
	Buffer msg;

	buffer_init(&msg);
	buffer_put_char(&msg, code);
	buffer_put_int(&msg, id);
	buffer_put_string(&msg, s, len);
	send_msg(fd, &msg);
	debug3("Sent message fd %d T:%d I:%d", fd, code, id);
	buffer_free(&msg);
}

void
send_string_attrs_request(int fd, u_int id, u_int code, char *s,
    u_int len, Attrib *a)
{
	Buffer msg;

	buffer_init(&msg);
	buffer_put_char(&msg, code);
	buffer_put_int(&msg, id);
	buffer_put_string(&msg, s, len);
	encode_attrib(&msg, a);
	send_msg(fd, &msg);
	debug3("Sent message fd %d T:%d I:%d", fd, code, id);
	buffer_free(&msg);
}

u_int
get_status(int fd, int expected_id)
{
	Buffer msg;
	u_int type, id, status;

	buffer_init(&msg);
	get_msg(fd, &msg);
	type = buffer_get_char(&msg);
	id = buffer_get_int(&msg);

	if (id != expected_id)
		fatal("ID mismatch (%d != %d)", id, expected_id);
	if (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%d) packet, got %d",
		    SSH2_FXP_STATUS, type);

	status = buffer_get_int(&msg);
	buffer_free(&msg);

	debug3("SSH2_FXP_STATUS %d", status);

	return(status);
}

char *
get_handle(int fd, u_int expected_id, u_int *len)
{
	Buffer msg;
	u_int type, id;
	char *handle;

	buffer_init(&msg);
	get_msg(fd, &msg);
	type = buffer_get_char(&msg);
	id = buffer_get_int(&msg);

	if (id != expected_id)
		fatal("ID mismatch (%d != %d)", id, expected_id);
	if (type == SSH2_FXP_STATUS) {
		int status = buffer_get_int(&msg);

		error("Couldn't get handle: %s", fx2txt(status));
		return(NULL);
	} else if (type != SSH2_FXP_HANDLE)
		fatal("Expected SSH2_FXP_HANDLE(%d) packet, got %d",
		    SSH2_FXP_HANDLE, type);

	handle = buffer_get_string(&msg, len);
	buffer_free(&msg);

	return(handle);
}

Attrib *
get_decode_stat(int fd, u_int expected_id)
{
	Buffer msg;
	u_int type, id;
	Attrib *a;

	buffer_init(&msg);
	get_msg(fd, &msg);

	type = buffer_get_char(&msg);
	id = buffer_get_int(&msg);

	debug3("Received stat reply T:%d I:%d", type, id);
	if (id != expected_id)
		fatal("ID mismatch (%d != %d)", id, expected_id);
	if (type == SSH2_FXP_STATUS) {
		int status = buffer_get_int(&msg);

		error("Couldn't stat remote file: %s", fx2txt(status));
		return(NULL);
	} else if (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%d) packet, got %d",
		    SSH2_FXP_ATTRS, type);
	}
	a = decode_attrib(&msg);
	buffer_free(&msg);

	return(a);
}

int
do_init(int fd_in, int fd_out)
{
	int type, version;
	Buffer msg;

	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_INIT);
	buffer_put_int(&msg, SSH2_FILEXFER_VERSION);
	send_msg(fd_out, &msg);

	buffer_clear(&msg);

	get_msg(fd_in, &msg);

	/* Expecting a VERSION reply */
	if ((type = buffer_get_char(&msg)) != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %d)",
		    type);
		buffer_free(&msg);
		return(-1);
	}
	version = buffer_get_int(&msg);

	debug2("Remote version: %d", version);

	/* Check for extensions */
	while (buffer_len(&msg) > 0) {
		char *name = buffer_get_string(&msg, NULL);
		char *value = buffer_get_string(&msg, NULL);

		debug2("Init extension: \"%s\"", name);
		xfree(name);
		xfree(value);
	}

	buffer_free(&msg);
	return(0);
}

int
do_close(int fd_in, int fd_out, char *handle, u_int handle_len)
{
	u_int id, status;
	Buffer msg;

	buffer_init(&msg);

	id = msg_id++;
	buffer_put_char(&msg, SSH2_FXP_CLOSE);
	buffer_put_int(&msg, id);
	buffer_put_string(&msg, handle, handle_len);
	send_msg(fd_out, &msg);
	debug3("Sent message SSH2_FXP_CLOSE I:%d", id);

	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't close file: %s", fx2txt(status));

	buffer_free(&msg);

	return(status);
}

int
do_ls(int fd_in, int fd_out, char *path)
{
	Buffer msg;
	u_int type, id, handle_len, i, expected_id;
	char *handle;

	id = msg_id++;

	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_OPENDIR);
	buffer_put_int(&msg, id);
	buffer_put_cstring(&msg, path);
	send_msg(fd_out, &msg);

	buffer_clear(&msg);

	handle = get_handle(fd_in, id, &handle_len);
	if (handle == NULL)
		return(-1);

	for(;;) {
		int count;

		id = expected_id = msg_id++;

		debug3("Sending SSH2_FXP_READDIR I:%d", id);

		buffer_clear(&msg);
		buffer_put_char(&msg, SSH2_FXP_READDIR);
		buffer_put_int(&msg, id);
		buffer_put_string(&msg, handle, handle_len);
		send_msg(fd_out, &msg);

		buffer_clear(&msg);

		get_msg(fd_in, &msg);

		type = buffer_get_char(&msg);
		id = buffer_get_int(&msg);

		debug3("Received reply T:%d I:%d", type, id);

		if (id != expected_id)
			fatal("ID mismatch (%d != %d)", id, expected_id);

		if (type == SSH2_FXP_STATUS) {
			int status = buffer_get_int(&msg);

			debug3("Received SSH2_FXP_STATUS %d", status);

			if (status == SSH2_FX_EOF) {
				break;
			} else {
				error("Couldn't read directory: %s",
				    fx2txt(status));
				do_close(fd_in, fd_out, handle, handle_len);
				return(NULL);
			}
		} else if (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%d) packet, got %d",
			    SSH2_FXP_NAME, type);

		count = buffer_get_int(&msg);
		debug3("Received %i SSH2_FXP_NAME responses", count);
		for(i = 0; i < count; i++) {
			char *filename, *longname;
			Attrib *a;

			filename = buffer_get_string(&msg, NULL);
			longname = buffer_get_string(&msg, NULL);
			a = decode_attrib(&msg);

			printf("%s\n", longname);

			xfree(filename);
			xfree(longname);
		}
	}

	buffer_free(&msg);
	do_close(fd_in, fd_out, handle, handle_len);
	xfree(handle);

	return(0);
}

int
do_rm(int fd_in, int fd_out, char *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = msg_id++;
	send_string_request(fd_out, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't delete file: %s", fx2txt(status));
	return(status);
}

int
do_mkdir(int fd_in, int fd_out, char *path, Attrib *a)
{
	u_int status, id;

	id = msg_id++;
	send_string_attrs_request(fd_out, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't create directory: %s", fx2txt(status));

	return(status);
}

int
do_rmdir(int fd_in, int fd_out, char *path)
{
	u_int status, id;

	id = msg_id++;
	send_string_request(fd_out, id, SSH2_FXP_RMDIR, path, strlen(path));

	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't remove directory: %s", fx2txt(status));

	return(status);
}

Attrib *
do_stat(int fd_in, int fd_out, char *path)
{
	u_int id;

	id = msg_id++;
	send_string_request(fd_out, id, SSH2_FXP_STAT, path, strlen(path));
	return(get_decode_stat(fd_in, id));
}

Attrib *
do_lstat(int fd_in, int fd_out, char *path)
{
	u_int id;

	id = msg_id++;
	send_string_request(fd_out, id, SSH2_FXP_LSTAT, path, strlen(path));
	return(get_decode_stat(fd_in, id));
}

Attrib *
do_fstat(int fd_in, int fd_out, char *handle,
    u_int handle_len)
{
	u_int id;

	id = msg_id++;
	send_string_request(fd_out, id, SSH2_FXP_FSTAT, handle, handle_len);
	return(get_decode_stat(fd_in, id));
}

int
do_setstat(int fd_in, int fd_out, char *path, Attrib *a)
{
	u_int status, id;

	id = msg_id++;
	send_string_attrs_request(fd_out, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't setstat on \"%s\": %s", path,
		    fx2txt(status));

	return(status);
}

int
do_fsetstat(int fd_in, int fd_out, char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	id = msg_id++;
	send_string_attrs_request(fd_out, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't fsetstat: %s", fx2txt(status));

	return(status);
}

char *
do_realpath(int fd_in, int fd_out, char *path)
{
	Buffer msg;
	u_int type, expected_id, count, id;
	char *filename, *longname;
	Attrib *a;

	expected_id = id = msg_id++;
	send_string_request(fd_out, id, SSH2_FXP_REALPATH, path,
	    strlen(path));

	buffer_init(&msg);

	get_msg(fd_in, &msg);
	type = buffer_get_char(&msg);
	id = buffer_get_int(&msg);

	if (id != expected_id)
		fatal("ID mismatch (%d != %d)", id, expected_id);

	if (type == SSH2_FXP_STATUS) {
		u_int status = buffer_get_int(&msg);

		error("Couldn't canonicalise: %s", fx2txt(status));
		return(NULL);
	} else if (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%d) packet, got %d",
		    SSH2_FXP_NAME, type);

	count = buffer_get_int(&msg);
	if (count != 1)
		fatal("Got multiple names (%d) from SSH_FXP_REALPATH", count);

	filename = buffer_get_string(&msg, NULL);
	longname = buffer_get_string(&msg, NULL);
	a = decode_attrib(&msg);

	debug3("SSH_FXP_REALPATH %s -> %s", path, filename);

	xfree(longname);

	buffer_free(&msg);

	return(filename);
}

int
do_rename(int fd_in, int fd_out, char *oldpath, char *newpath)
{
	Buffer msg;
	u_int status, id;

	buffer_init(&msg);

	/* Send rename request */
	id = msg_id++;
	buffer_put_char(&msg, SSH2_FXP_RENAME);
	buffer_put_int(&msg, id);
	buffer_put_cstring(&msg, oldpath);
	buffer_put_cstring(&msg, newpath);
	send_msg(fd_out, &msg);
	debug3("Sent message SSH2_FXP_RENAME \"%s\" -> \"%s\"", oldpath,
	    newpath);
	buffer_free(&msg);

	status = get_status(fd_in, id);
	if (status != SSH2_FX_OK)
		error("Couldn't rename file \"%s\" to \"%s\": %s", oldpath, newpath,
		    fx2txt(status));

	return(status);
}

int
do_download(int fd_in, int fd_out, char *remote_path, char *local_path,
    int pflag)
{
	int local_fd;
	u_int expected_id, handle_len, mode, type, id;
	u_int64_t offset;
	char *handle;
	Buffer msg;
	Attrib junk, *a;

	a = do_stat(fd_in, fd_out, remote_path);
	if (a == NULL)
		return(-1);

	/* XXX: should we preserve set[ug]id? */
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = S_IWRITE | (a->perm & 0777);
	else
		mode = 0666;

	local_fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (local_fd == -1) {
		error("Couldn't open local file \"%s\" for writing: %s",
		    local_path, strerror(errno));
		return(errno);
	}

	/* Override umask and utimes if asked */
	if (pflag && fchmod(local_fd, mode) == -1)
		error("Couldn't set mode on \"%s\": %s", local_path,
		    strerror(errno));
	if (pflag && (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
		struct timeval tv;

		tv.tv_sec = a->atime;
		tv.tv_usec = a->mtime;
		if (utimes(local_path, &tv) == -1)
			error("Can't set times on \"%s\": %s", local_path,
			    strerror(errno));
	}

	buffer_init(&msg);

	/* Send open request */
	id = msg_id++;
	buffer_put_char(&msg, SSH2_FXP_OPEN);
	buffer_put_int(&msg, id);
	buffer_put_cstring(&msg, remote_path);
	buffer_put_int(&msg, SSH2_FXF_READ);
	attrib_clear(&junk); /* Send empty attributes */
	encode_attrib(&msg, &junk);
	send_msg(fd_out, &msg);
	debug3("Sent message SSH2_FXP_OPEN I:%d P:%s", id, remote_path);

	handle = get_handle(fd_in, id, &handle_len);
	if (handle == NULL) {
		buffer_free(&msg);
		close(local_fd);
		return(-1);
	}

	/* Read from remote and write to local */
	offset = 0;
	for(;;) {
		u_int len;
		char *data;

		id = expected_id = msg_id++;

		buffer_clear(&msg);
		buffer_put_char(&msg, SSH2_FXP_READ);
		buffer_put_int(&msg, id);
		buffer_put_string(&msg, handle, handle_len);
		buffer_put_int64(&msg, offset);
		buffer_put_int(&msg, COPY_SIZE);
		send_msg(fd_out, &msg);
		debug3("Sent message SSH2_FXP_READ I:%d O:%llu S:%u",
		    id, (unsigned long long)offset, COPY_SIZE);

		buffer_clear(&msg);

		get_msg(fd_in, &msg);
		type = buffer_get_char(&msg);
		id = buffer_get_int(&msg);
		debug3("Received reply T:%d I:%d", type, id);
		if (id != expected_id)
			fatal("ID mismatch (%d != %d)", id, expected_id);
		if (type == SSH2_FXP_STATUS) {
			int status = buffer_get_int(&msg);

			if (status == SSH2_FX_EOF)
				break;
			else {
				error("Couldn't read from remote "
				    "file \"%s\" : %s", remote_path,
				     fx2txt(status));
				do_close(fd_in, fd_out, handle, handle_len);
				xfree(handle);
				close(local_fd);
				buffer_free(&msg);
				return(status);
			}
		} else if (type != SSH2_FXP_DATA) {
			fatal("Expected SSH2_FXP_DATA(%d) packet, got %d",
			    SSH2_FXP_DATA, type);
		}

		data = buffer_get_string(&msg, &len);
		if (len > COPY_SIZE)
			fatal("Received more data than asked for %d > %d",
			    len, COPY_SIZE);

		debug3("In read loop, got %d offset %lld", len,
		    (unsigned long long)offset);
		if (atomicio(write, local_fd, data, len) != len) {
			error("Couldn't write to \"%s\": %s", local_path,
			    strerror(errno));
			do_close(fd_in, fd_out, handle, handle_len);
			xfree(handle);
			close(local_fd);
			xfree(data);
			buffer_free(&msg);
			return(-1);
		}

		offset += len;
		xfree(data);
	}
	xfree(handle);
	buffer_free(&msg);
	close(local_fd);

	return(do_close(fd_in, fd_out, handle, handle_len));
}

int
do_upload(int fd_in, int fd_out, char *local_path, char *remote_path,
    int pflag)
{
	int local_fd;
	u_int handle_len, id;
	u_int64_t offset;
	char *handle;
	Buffer msg;
	struct stat sb;
	Attrib a;

	if ((local_fd = open(local_path, O_RDONLY, 0)) == -1) {
		error("Couldn't open local file \"%s\" for reading: %s",
		    local_path, strerror(errno));
		return(-1);
	}
	if (fstat(local_fd, &sb) == -1) {
		error("Couldn't fstat local file \"%s\": %s",
		    local_path, strerror(errno));
		close(local_fd);
		return(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	if (!pflag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	buffer_init(&msg);

	/* Send open request */
	id = msg_id++;
	buffer_put_char(&msg, SSH2_FXP_OPEN);
	buffer_put_int(&msg, id);
	buffer_put_cstring(&msg, remote_path);
	buffer_put_int(&msg, SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC);
	encode_attrib(&msg, &a);
	send_msg(fd_out, &msg);
	debug3("Sent message SSH2_FXP_OPEN I:%d P:%s", id, remote_path);

	buffer_clear(&msg);

	handle = get_handle(fd_in, id, &handle_len);
	if (handle == NULL) {
		close(local_fd);
		buffer_free(&msg);
		return(-1);
	}

	/* Override umask and utimes if asked */
	if (pflag)
		do_fsetstat(fd_in, fd_out, handle, handle_len, &a);

	/* Read from local and write to remote */
	offset = 0;
	for(;;) {
		int len;
		char data[COPY_SIZE];
		u_int status;

		/*
		 * Can't use atomicio here because it returns 0 on EOF, thus losing
		 * the last block of the file
		 */
		do
			len = read(local_fd, data, COPY_SIZE);
		while ((len == -1) && (errno == EINTR || errno == EAGAIN));

		if (len == -1)
			fatal("Couldn't read from \"%s\": %s", local_path,
			    strerror(errno));
		if (len == 0)
			break;

		buffer_clear(&msg);
		buffer_put_char(&msg, SSH2_FXP_WRITE);
		buffer_put_int(&msg, ++id);
		buffer_put_string(&msg, handle, handle_len);
		buffer_put_int64(&msg, offset);
		buffer_put_string(&msg, data, len);
		send_msg(fd_out, &msg);
		debug3("Sent message SSH2_FXP_WRITE I:%d O:%llu S:%u",
		    id, (unsigned long long)offset, len);

		status = get_status(fd_in, id);
		if (status != SSH2_FX_OK) {
			error("Couldn't write to remote file \"%s\": %s",
			    remote_path, fx2txt(status));
			do_close(fd_in, fd_out, handle, handle_len);
			xfree(handle);
			close(local_fd);
			return(-1);
		}
		debug3("In write loop, got %d offset %llu", len,
		    (unsigned long long)offset);

		offset += len;
	}
	xfree(handle);
	buffer_free(&msg);

	if (close(local_fd) == -1) {
		error("Couldn't close local file \"%s\": %s", local_path,
		    strerror(errno));
		do_close(fd_in, fd_out, handle, handle_len);
		return(-1);
	}

	return(do_close(fd_in, fd_out, handle, handle_len));
}
