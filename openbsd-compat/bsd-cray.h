
#ifndef _BSD_CRAY_H
#define _BSD_CRAY_H

#ifdef _CRAY
void    cray_init_job(struct passwd *);         /* init cray job */
void    cray_job_termination_handler(int);      /* process end of job signal */
void    cray_setup(uid_t, char *);              /* set cray limits */
extern  char   cray_tmpdir[];                   /* cray tmpdir */
#endif


#endif /* _BSD_CRAY_H */
