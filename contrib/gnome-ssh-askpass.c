/*
   Compile with:

   cc `gnome-config --cflags gnome gnomeui` \
     gnome-ssh-askpass.c -o gnome-ssh-askpass \
     `gnome-config --libs gnome gnomeui`

*/

/*
**
** GNOME ssh passphrase requestor
**
** Damien Miller <djm@ibs.com.au>
** 
** Copyright 1999 Internet Business Solutions
**
** Permission is hereby granted, free of charge, to any person
** obtaining a copy of this software and associated documentation
** files (the "Software"), to deal in the Software without
** restriction, including without limitation the rights to use, copy,
** modify, merge, publish, distribute, sublicense, and/or sell copies
** of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
** KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
** WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
** AND NONINFRINGEMENT.  IN NO EVENT SHALL DAMIEN MILLER OR INTERNET
** BUSINESS SOLUTIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
** ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
** OR OTHER DEALINGS IN THE SOFTWARE.
**
** Except as contained in this notice, the name of Internet Business
** Solutions shall not be used in advertising or otherwise to promote
** the sale, use or other dealings in this Software without prior
** written authorization from Internet Business Solutions.
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gnome.h>
#include <X11/Xlib.h>
#include <gdk/gdkx.h>

void
report_failed_grab (void)
{
	GtkWidget *err;

	err = gnome_message_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_MESSAGE_BOX_ERROR, "EXIT", NULL);
	gtk_window_set_position(GTK_WINDOW(err), GTK_WIN_POS_CENTER);
	gtk_object_set(GTK_OBJECT(err), "type", GTK_WINDOW_POPUP, NULL);

	gnome_dialog_run_and_close(GNOME_DIALOG(err));
}

void
passphrase_dialog(char *message)
{
	char *passphrase;
	int result;
	
	GtkWidget *dialog, *entry, *label;

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK, 
									  GNOME_STOCK_BUTTON_CANCEL, NULL);

	label = gtk_label_new(message);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox), label, FALSE, 
							 FALSE, 0);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox), entry, FALSE, 
							 FALSE, 0);
	gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
	gtk_widget_grab_focus(entry);

	/* Center window and prepare for grab */
	gtk_object_set(GTK_OBJECT(dialog), "type", GTK_WINDOW_POPUP, NULL);
	gnome_dialog_set_default(GNOME_DIALOG(dialog), 0);
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_policy(GTK_WINDOW(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_set_border_width(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox), GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	XGrabServer(GDK_DISPLAY());
	if (gdk_pointer_grab(dialog->window, TRUE, 0,
			     NULL, NULL, GDK_CURRENT_TIME))
		goto nograb;
	if (gdk_keyboard_grab(dialog->window, FALSE, GDK_CURRENT_TIME))
		goto nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(entry));

	/* Run dialog */
	result = gnome_dialog_run(GNOME_DIALOG(dialog));

	/* Ungrab */
	XUngrabServer(GDK_DISPLAY());
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_entry_get_text(GTK_ENTRY(entry));
	if (result == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', strlen(passphrase));
	gtk_entry_set_text(GTK_ENTRY(entry), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	return;

	/* At least one grab failed - ungrab what we got, and report
	   the failure to the user.  Note that XGrabServer() cannot
	   fail.  */
 nograbkb:
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
}

int
main(int argc, char **argv)
{
	char *message;
	
	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	if (argc == 2)
		message = argv[1];
	else
		message = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	passphrase_dialog(message);
	return 0;
}
