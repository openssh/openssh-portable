#ifndef AUTH_OPTIONS_H
#define AUTH_OPTIONS_H
/* Flags that may be set in authorized_keys options. */
extern int no_port_forwarding_flag;
extern int no_agent_forwarding_flag;
extern int no_x11_forwarding_flag;
extern int no_pty_flag;
extern char *forced_command;
extern struct envstring *custom_environment;

/* return 1 if access is granted, 0 if not. side effect: sets key option flags */
int	auth_parse_options(struct passwd *pw, char *options, unsigned long linenum);
#endif
