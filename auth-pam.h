#include "includes.h"
#ifdef USE_PAM

#include <pwd.h> /* For struct passwd */

void start_pam(struct passwd *pw);
void finish_pam(void);
int auth_pam_password(struct passwd *pw, const char *password);
char **fetch_pam_environment(void);
int do_pam_account(char *username, char *remote_user);
void do_pam_session(char *username, const char *ttyname);
void do_pam_setcred();
void print_pam_messages(void);

#endif /* USE_PAM */
