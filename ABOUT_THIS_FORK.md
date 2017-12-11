## Changes on this fork

* Disable backlog on container start/restart.
* Reconnect every second when syslog connection fails.
* Set syslog connection write deadline 10s to detect syslog in -sigstop state.
* Set syslog tcp/tls connection timeout to 10s.
* Do not lose messages during reconnect.

## Debugging

Start rsyslog on VM:

    systemctl start rsyslog

Run logspout:

    DEBUG=1 PORT=8080 go run *.go syslog+tcp://192.168.56.101:514

Build a test container from Dockerfile:

    FROM alpine:3.7
    RUN echo '#!/bin/ash' > /1.sh && echo 'while [ 1 ]; do date "+%s" ; sleep 1 ; done' >> /1.sh && chmod +x /1.sh
    CMD ["/1.sh"]

Run container:

    docker build -t test:1 .
    docker run --rm test:1

Watch rsyslog logs:

    tail -f /var/log/messages
