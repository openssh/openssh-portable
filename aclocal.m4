dnl $Id: aclocal.m4,v 1.1 2000/05/01 23:57:51 damien Exp $
dnl
dnl OpenSSH-specific autoconf macros
dnl

dnl AC_PATH_ENTROPY_PROG(variablename, command):
dnl Tidiness function, sets 'undef' if not found, and does the AC_SUBST
AC_DEFUN(AC_PATH_ENTROPY_PROG, [
	AC_PATH_PROG([$1], [$2])
	if test -z "[$]$1" ; then
		$1="undef"
	fi
	AC_SUBST([$1])
])

