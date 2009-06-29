#ifndef _OBFUSCATE_H
#define _OBFUSCATE_H

void obfuscate_receive_seed(int);
void obfuscate_send_seed(int);
void obfuscate_set_keyword(const char *);
void obfuscate_input(u_char *, u_int);
void obfuscate_output(u_char *, u_int);

#endif
