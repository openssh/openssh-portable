#ifndef AUTH_H
#define AUTH_H

void	do_authentication(void);
void	do_authentication2(void);

struct passwd *
auth_get_user(void);

#endif
