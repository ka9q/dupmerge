#
# Regular cron jobs for the dupmerge package.
#
0 4	* * *	root	[ -x /usr/bin/dupmerge_maintenance ] && /usr/bin/dupmerge_maintenance
