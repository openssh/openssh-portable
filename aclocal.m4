dnl $Id: aclocal.m4,v 1.4 2000/06/26 00:20:19 djm Exp $
dnl
dnl OpenSSH-specific autoconf macros
dnl


dnl OSSH_CHECK_HEADER_FOR_FIELD(field, header, symbol)
dnl Does AC_EGREP_HEADER on 'header' for the string 'field'
dnl If found, set 'symbol' to be defined. Cache the result.
dnl TODO: This is not foolproof, better to compile and read from there
AC_DEFUN(OSSH_CHECK_HEADER_FOR_FIELD, [
# look for field '$1' in header '$2'
	dnl This strips characters illegal to m4 from the header filename
	ossh_safe=`echo "$2" | sed 'y%./+-%__p_%'`
	dnl
	ossh_varname="ossh_cv_$ossh_safe""_has_"$1
	AC_MSG_CHECKING(for $1 field in $2)
	AC_CACHE_VAL($ossh_varname, [
		AC_EGREP_HEADER($1, $2, [ dnl
			eval "$ossh_varname=yes" dnl
		], [ dnl
			eval "$ossh_varname=no" dnl
		]) dnl
	])
	ossh_result=`eval 'echo $'"$ossh_varname"`
	if test -n "`echo $ossh_varname`"; then
		AC_MSG_RESULT($ossh_result)
		if test "x$ossh_result" = "xyes"; then
			AC_DEFINE($3)
		fi
	else
		AC_MSG_RESULT(no)
	fi
])

dnl OSSH_PATH_ENTROPY_PROG(variablename, command):
dnl Tidiness function, sets 'undef' if not found, and does the AC_SUBST
AC_DEFUN(OSSH_PATH_ENTROPY_PROG, [
	AC_PATH_PROG($1, $2)
	if test -z "[$]$1" ; then
		$1="undef"
	fi
	AC_SUBST($1)
])

