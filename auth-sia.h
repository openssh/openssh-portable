#include "includes.h"

#ifdef HAVE_OSF_SIA

int	auth_sia_password(Authctxt *authctxt, char *pass);
void	session_setup_sia(char *user, char *tty);

#endif /* HAVE_OSF_SIA */
