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

int passphrase_dialog(char **passphrase_p, char *message)
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
	gdk_pointer_grab(dialog->window, TRUE, 0, NULL, NULL, GDK_CURRENT_TIME);
	gdk_keyboard_grab(dialog->window, FALSE, GDK_CURRENT_TIME);

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(entry));

	/* Run dialog */
	result = gnome_dialog_run(GNOME_DIALOG(dialog));
		
	/* Ungrab */
	XUngrabServer(GDK_DISPLAY());
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	passphrase = gtk_entry_get_text(GTK_ENTRY(entry));

	/* Take copy of passphrase if user selected OK */
	if (result == 0)	
		*passphrase_p = strdup(passphrase);
	else
		*passphrase_p = NULL;
		
	/* Zero existing passphrase */
	memset(passphrase, '\0', strlen(passphrase));
	gtk_entry_set_text(GTK_ENTRY(entry), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));

 	return (result == 0);
}

int main(int argc, char **argv)
{
	char *passphrase;
	char *message;
	
	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	if (argc == 2)
		message = argv[1];
	else
		message = "Enter your OpenSSH passphrase:";

	if (passphrase_dialog(&passphrase, message))
	{
		puts(passphrase);
		memset(passphrase, '\0', strlen(passphrase));
	}
	
	return 0;
}
