#ifndef MATCH_H
#define MATCH_H

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 */
int     match_pattern(const char *s, const char *pattern);

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
int     match_hostname(const char *host, const char *pattern, unsigned int len);

#endif
