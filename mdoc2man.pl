#!/usr/bin/perl
###
### Quick usage:  mdoc2man.pl < mdoc_manpage.8 > man_manpage.8
###
###
###  Copyright (c) 2001 University of Illinois Board of Trustees
###  Copyright (c) 2001 Mark D. Roth
###  All rights reserved.
### 
###  Redistribution and use in source and binary forms, with or without
###  modification, are permitted provided that the following conditions
###  are met:
###  1. Redistributions of source code must retain the above copyright
###     notice, this list of conditions and the following disclaimer.
###  2. Redistributions in binary form must reproduce the above copyright
###     notice, this list of conditions and the following disclaimer in the
###     documentation and/or other materials provided with the distribution.
###  3. All advertising materials mentioning features or use of this software
###     must display the following acknowledgement:
###     This product includes software developed by the University of
###     Illinois at Urbana, and their contributors.
###  4. The University nor the names of their
###     contributors may be used to endorse or promote products derived from
###     this software without specific prior written permission.
### 
###  THIS SOFTWARE IS PROVIDED BY THE TRUSTEES AND CONTRIBUTORS ``AS IS'' AND
###  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
###  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
###  ARE DISCLAIMED.  IN NO EVENT SHALL THE TRUSTEES OR CONTRIBUTORS BE LIABLE
###  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
###  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
###  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
###  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
###  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
###  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
###  SUCH DAMAGE.
###

use strict;

my ($name, $date, $id);
my ($line);
my ($optlist, $nospace, $enum, $synopsis);


$optlist = 0;		### 1 = bullet, 2 = enum, 3 = tag
$nospace = 0;
$synopsis = 0;

while ($line = <STDIN>)
{
	if ($line !~ /^\./)
	{
		print $line;
		next;
	}

	$line =~ s/^\.//;

	next
		if ($line =~ m/\\"/);

	$line = ParseMacro($line);
	print($line)
		if (defined $line);
}



sub ParseMacro # ($line)
{
	my ($line) = @_;
	my (@words, $retval, $option, $parens, $arg);

	@words = split(/\s+/, $line);
	$retval = '';
	$option = 0;
	$parens = 0;
	$arg = 0;

#	print('@words = ', scalar(@words), ': ', join(' ', @words), "\n");

	while ($_ = shift @words)
	{
#		print "WORD: $_\n";

		next
			if (/^(Li|Pf|X[oc])$/);

		if (/^Ns/)
		{
			$nospace = 1
				if (! $nospace);
			$retval =~ s/ $//;
			next;
		}

		if (/^No/)
		{
			$retval =~ s/ $//;
			$retval .= shift @words;
			next;
		}

		if (/^Dq$/) {
			$retval .= '``' . (shift @words) . '\'\'';
			$nospace = 1
				if (! $nospace && $words[0] =~ m/^[\.,]/);
			next;
		}

		if (/^(Sq|Ql)$/) {
			$retval .= '`' . (shift @words) . '\'';
			$nospace = 1
				if (! $nospace && $words[0] =~ m/^[\.,]/);
			next;
		}

		$retval .= ' '
			if (! $nospace && $retval ne '' && $retval !~ m/[\n ]$/);
		$nospace = 0
			if ($nospace == 1);

		if (/^Dd$/) {
			$date = join(' ', @words);
			return undef;
		}

		if (/^Dt$/) {
			$id = join(' ', @words);
			return undef;
		}

		if (/^Os$/) {
			$retval .= '.TH '
				. $id
				. " \"$date\" \""
				. join(' ', @words)
				. "\"";
			last;
		}

		if (/^Sh$/) {
			$retval .= '.SH';
			if ($words[0] eq 'SYNOPSIS')
			{
				$synopsis = 1;
			}
			else
			{
				$synopsis = 0;
			}
			next;
		}

		if (/^Xr$/) {
			$retval .= '\\fB' . (shift @words) .
				'\\fR(' . (shift @words) . ')'
				. (shift @words);
			last;
		}

		if (/^Nm$/) {
			$name = shift @words
				if (@words > 0);
			$retval .= ".br\n"
				if ($synopsis);
			$retval .= "\\fB$name\\fR";
			$nospace = 1
				if (! $nospace && $words[0] =~ m/^[\.,]/);
			next;
		}

		if (/^Nd$/) {
			$retval .= '\\-';
			next;
		}

		if (/^Fl$/) {
			$retval .= '\\fB\\-' . (shift @words) . '\\fR';
			$nospace = 1
				if (! $nospace && $words[0] =~ m/^[\.,]/);
			next;
		}

		if (/^Ar$/) {
			$retval .= '\\fI';
			if (! defined $words[0])
			{
				$retval .= 'file ...\\fR';
			}
			$arg = 1;
			$nospace = 1
				if (! $nospace);
			next;
		}

		if (/^Cm$/) {
			$retval .= '\\fB' . (shift @words) . '\\fR';
			next;
		}

		if (/^Op$/) {
			$option = 1;
			$nospace = 1
				if (! $nospace);
			$retval .= '[';
			next;
		}

		if (/^Oo$/) {
			$retval .= "[\\c\n";
			next;
		}

		if (/^Oc$/) {
			$retval .= ']';
			next;
		}

		if (/^Pp$/) {
			if ($optlist) {
				$retval .= "\n";
			} else {
				$retval .= '.LP';
			}
			next;
		}

		if (/^Ss$/) {
			$retval .= '.SS';
			next;
		}

		if (/^Pa$/ && ! $option) {
			$retval .= '\\fI';
			$retval .= '\\&'
				if ($words[0] =~ m/^\./);
			$retval .= (shift @words) . '\\fR';
			$nospace = 1
				if (! $nospace && $words[0] =~ m/^[\.,]/);
			next;
		}

		if (/^Dv$/) {
			$retval .= '.BR';
			next;
		}

		if (/^(Em|Ev)$/) {
			$retval .= '.IR';
			next;
		}

		if (/^Pq$/) {
			$retval .= '(';
			$nospace = 1;
			$parens = 1;
			next;
		}

		if (/^(S[xy])$/) {
			$retval .= '.B ' . join(' ', @words);
			last;
		}

		if (/^Ic$/)
		{
			$retval .= '\\fB';
			while (defined $words[0]
				&& $words[0] !~ m/^[\.,]/)
			{
				$retval .= shift @words;
				$retval .= ' '
					if (! $nospace);
			}
			$retval =~ s/ $//;
			$retval .= '\\fR';
			$retval .= shift @words
				if (defined $words[0]);
			last;
		}

		if (/^Bl$/) {
			if ($words[0] eq '-bullet') {
				$optlist = 1;
			} elsif ($words[0] eq '-enum') {
				$optlist = 2;
				$enum = 0;
			} elsif ($words[0] eq '-tag') {
				$optlist = 3;
			}
			last;
		}

		if (/^El$/) {
			$optlist = 0;
			next;
		}

		if ($optlist && /^It$/) {
			if ($optlist == 1) {
				# bullets
				$retval .= '.IP \\(bu';
				next;
			}

			if ($optlist == 2) {
				# enum
				$retval .= '.IP ' . (++$enum) . '.';
				next;
			}

			if ($optlist == 3) {
				# tags
				$retval .= ".TP\n";
				if ($words[0] =~ m/^(Pa|Ev)$/)
				{
					shift @words;
					$retval .= '.B';
				}
				next;
			}

			next;
		}

		if (/^Sm$/) {
			if ($words[0] eq 'off') {
				$nospace = 2;
			} elsif ($words[0] eq 'on') {
				$retval .= "\n";
				$nospace = 0;
			}
			shift @words;
			next;
		}

		$retval .= "$_";
	}

	return undef
		if ($retval eq '.');

	$retval =~ s/^\.([^a-zA-Z])/$1/;
	$retval =~ s/ $//;

	$retval .= ')'
		if ($parens == 1);

	$retval .= ']'
		if ($option == 1);

	$retval .= '\\fR'
		if ($arg);

	$retval .= '\\c'
		if ($nospace && $retval ne '' && $retval !~ m/\n$/);

	$retval .= "\n"
		if ($retval ne '' && $retval !~ m/\n$/);

	return $retval;
}
