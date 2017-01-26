## Changes on this fork

* Disable backlog on container start/restart.
* Reconnect when syslog connection is failed every 2s.
* Set syslog connection deadline 10s to detect syslog in -sigstop state.
