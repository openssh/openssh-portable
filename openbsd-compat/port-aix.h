#ifdef _AIX

#ifdef HAVE_GETUSERATTR
void set_limit(char *user, char *soft, char *hard, int resource, int mult);
void set_limits_from_userattr(char *user);
#endif /* HAVE_GETUSERATTR */

void aix_usrinfo(struct passwd *pw, char *tty, int ttyfd);

#endif /* _AIX */
