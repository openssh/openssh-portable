#!/bin/bash

# ssh-agent lock_script for the 'screen' terminal multiplexer
#
# use it with
#   ssh-agent -l <path/to/this/script>
#
# screen sets and unsets the execute bit on it's socket when
# the screen is attached/detached. We use this to decide whether
# the ssh-agent should consider itself unlocked or locked.

SOCKETDIR=/var/run/screen/S-`whoami`

# There might be several screen sessions for this user.
# Which one do we use?
if [ -z "$STY" ]; then
	# use newest socket file, meaing the most recently created session.
	SOCK=`ls -tr $SOCKETDIR | tail -1`
	if [ -z "$SOCK" ]; then
		# no socket -> no screen
		echo 1
		exit 1
	fi
	SOCKETNAME="$SOCKETDIR/$SOCK"
else
        # this script actually runs inside of a screen session. So
	# the agent also runs inside this screen session -> use this one.
	SOCKETNAME="$SOCKETDIR/$STY"
fi

if [ -x $SOCKETNAME ]; then
	echo 0
	exit 0
else
	echo 1
	exit 1
fi

