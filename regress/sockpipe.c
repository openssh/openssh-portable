/*
 * Copyright (c) 2026 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Spawn a child command with one end of a bidirectional AF_UNIX socketpair(2)
 * attached to both its stdin and stdout, and relay between sockpipe's own
 * stdin/stdout and the peer socketpair end.
 *
 * When sockpipe reaches EOF on stdin, it calls shutdown(SHUT_WR) on the
 * socketpair rather than closing it, allowing tests to exercise socket
 * half-close behavior when a command (such as "ssh -W") shares a single
 * socket across stdin and stdout.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct pollfd pfd[2];
	char buf[8192];
	int sp[2], in_open = 1, sock_open = 1, nfd, i, status;
	ssize_t r, w, written;
	pid_t pid;

	if (argc < 2) {
		fprintf(stderr, "usage: sockpipe prog [args ...]\n");
		return 1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1) {
		perror("socketpair");
		return 1;
	}
	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		close(sp[1]);
		if (dup2(sp[0], STDIN_FILENO) == -1 ||
		    dup2(sp[0], STDOUT_FILENO) == -1)
			_exit(1);
		if (sp[0] > STDOUT_FILENO)
			close(sp[0]);
		execvp(argv[1], &argv[1]);
		perror(argv[1]);
		_exit(1);
	}
	close(sp[0]);
	while (sock_open || in_open) {
		nfd = 0;
		if (in_open) {
			pfd[nfd].fd = STDIN_FILENO;
			pfd[nfd].events = POLLIN;
			nfd++;
		}
		if (sock_open) {
			pfd[nfd].fd = sp[1];
			pfd[nfd].events = POLLIN;
			nfd++;
		}
		if (nfd == 0)
			break;
		if (poll(pfd, nfd, -1) <= 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (i = 0; i < nfd; i++) {
			if (pfd[i].fd == STDIN_FILENO &&
			    (pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) {
				r = read(STDIN_FILENO, buf, sizeof(buf));
				if (r == -1 &&
				    (errno == EINTR || errno == EAGAIN))
					continue;
				if (r > 0) {
					written = 0;
					while (written < r) {
						w = write(sp[1], buf + written,
						    r - written);
						if (w == -1 && (errno == EINTR ||
						    errno == EAGAIN))
							continue;
						if (w <= 0) {
							in_open = 0;
							break;
						}
						written += w;
					}
				} else {
					in_open = 0;
					shutdown(sp[1], SHUT_WR);
				}
			} else if (pfd[i].fd == sp[1] &&
			    (pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) {
				r = read(sp[1], buf, sizeof(buf));
				if (r == -1 &&
				    (errno == EINTR || errno == EAGAIN))
					continue;
				if (r > 0) {
					written = 0;
					while (written < r) {
						w = write(STDOUT_FILENO,
						    buf + written, r - written);
						if (w == -1 && (errno == EINTR ||
						    errno == EAGAIN))
							continue;
						if (w <= 0) {
							sock_open = 0;
							break;
						}
						written += w;
					}
				} else {
					sock_open = 0;
				}
			}
		}
	}
	close(sp[1]);
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
