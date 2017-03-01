## Changes on this fork

* Disable backlog on container start/restart.
* Reconnect every 2s when syslog connection fails.
* Set syslog connection write deadline 10s to detect syslog in -sigstop state.
* Set syslog tcp/tls connection timeout to 10s.

