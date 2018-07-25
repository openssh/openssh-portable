/* 
 * Windows version of sshpty* routines in sshpty.c
 */



#include <Windows.h>
#include "..\..\..\sshpty.h"
#include "inc\unistd.h"
#include "misc_internal.h"

/* 
 * Windows versions of pty_*. Some of them are NO-OPs and should go 
 * away when pty logic is refactored and abstracted out 
 * 
 */

 /*
 * allocates a control channel for Windows PTY
 * ptyfd can be used to deliver Window size change events
 */
int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
	int p[2];
	*ttyfd = 0;
	*ptyfd = 0;
	if (w32_pipe(p) < 0)
		return 0;

	/* enable blocking mode io*/
	unset_nonblock(p[0]);
	unset_nonblock(p[1]);
	*ttyfd = p[0];
	*ptyfd = p[1];
	strlcpy(namebuf, "windows-pty", namebuflen);
	return 1;
}

void
pty_release(const char *tty) {
	/* NO-OP */
}

void
pty_make_controlling_tty(int *ttyfd, const char *tty) {
	/* NO-OP */
}

void
pty_change_window_size(int ptyfd, u_int row, u_int col,
    u_int xpixel, u_int ypixel) 
{
	unsigned short signalPacket[3];
	signalPacket[0] = PTY_SIGNAL_RESIZE_WINDOW;
	signalPacket[1] = col;
	signalPacket[2] = row;
	// TODO - xpixel, ypixel

	w32_write(ptyfd, signalPacket, sizeof(signalPacket));
}


void
pty_setowner(struct passwd *pw, const char *tty) {
	/* NO-OP */
}

void
disconnect_controlling_tty(void) {
	/* NO-OP */
}

