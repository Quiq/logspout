package syslog

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"
	"text/template"
	"time"

	"github.com/gliderlabs/logspout/router"
)

var hostname string

func init() {
	hostname, _ = os.Hostname()
	router.AdapterFactories.Register(NewSyslogAdapter, "syslog")
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func NewSyslogAdapter(route *router.Route) (router.LogAdapter, error) {
	transport, found := router.AdapterTransports.Lookup(route.AdapterTransport("udp"))
	if !found {
		return nil, errors.New("bad transport: " + route.Adapter)
	}
	conn, err := transport.Dial(route.Address, route.Options)
	if err != nil {
		return nil, err
	}

	format := getopt("SYSLOG_FORMAT", "rfc5424")
	priority := getopt("SYSLOG_PRIORITY", "{{.Priority}}")
	hostname := getopt("SYSLOG_HOSTNAME", "{{.Container.Config.Hostname}}")
	pid := getopt("SYSLOG_PID", "{{.Container.State.Pid}}")
	tag := getopt("SYSLOG_TAG", "{{.ContainerName}}"+route.Options["append_tag"])
	structuredData := getopt("SYSLOG_STRUCTURED_DATA", "")
	if route.Options["structured_data"] != "" {
		structuredData = route.Options["structured_data"]
	}
	data := getopt("SYSLOG_DATA", "{{.Data}}")

	if structuredData == "" {
		structuredData = "-"
	} else {
		structuredData = fmt.Sprintf("[%s]", structuredData)
	}

	var tmplStr string
	switch format {
	case "rfc5424":
		tmplStr = fmt.Sprintf("<%s>1 {{.Timestamp}} %s %s %s - %s %s\n",
			priority, hostname, tag, pid, structuredData, data)
	case "rfc3164":
		tmplStr = fmt.Sprintf("<%s>{{.Timestamp}} %s %s[%s]: %s\n",
			priority, hostname, tag, pid, data)
	default:
		return nil, errors.New("unsupported syslog format: " + format)
	}
	tmpl, err := template.New("syslog").Parse(tmplStr)
	if err != nil {
		return nil, err
	}
	return &SyslogAdapter{
		route:     route,
		conn:      conn,
		tmpl:      tmpl,
		transport: transport,
	}, nil
}

type SyslogAdapter struct {
	conn      net.Conn
	route     *router.Route
	tmpl      *template.Template
	transport router.AdapterTransport
}

func (a *SyslogAdapter) Stream(logstream chan *router.Message) {
	// When this function returns, logspout exits.
	for message := range logstream {
		m := &SyslogMessage{message}
		buf, err := m.Render(a.tmpl)
		// debugf("msg from chan: %s\n", m.Data)
		if err != nil {
			log.Println("syslog (render):", err)
			return
		}
		// It seems SetWriteDeadline() does not have any effect anymore.
		// When we pause rsyslog, it takes 55s to be detected.
		a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := a.conn.Write(buf); err != nil {
			fmt.Println("syslog:", err)
			switch a.conn.(type) {
			case *net.UDPConn:
				continue
			default:
				if err := a.retry(buf, err); err != nil {
					log.Println("syslog (retry):", err)
					return
				}
			}
		}
		a.conn.SetWriteDeadline(time.Time{})
	}
}

func (a *SyslogAdapter) retry(buf []byte, err error) error {
	if opError, ok := err.(*net.OpError); ok {
		if opError.Temporary() || opError.Timeout() {
			if err := a.resend(buf); err == nil {
				return nil
			}
		}
	}

	// reconnect forever
	a.reconnect()

	return a.resend(buf)
}

func (a *SyslogAdapter) resend(buf []byte) error {
	// 10 retries with exponential intervals 20ms .. 10.24s
	var err error
	try, tries := 0, 10
	for {
		debugf("retry #%d: %s\n", try+1, buf)
		_, err = a.conn.Write(buf)
		if err == nil {
			// retry successful
			return nil
		}

		try++
		if try > tries {
			// retry failed
			return err
		}

		time.Sleep((1 << uint(try)) * 10 * time.Millisecond)
	}
}

func (a *SyslogAdapter) reconnect() {
	// reconnecting every second until success
	a.conn.Close()
	i := 0
	for {
		conn, err := a.transport.Dial(a.route.Address, a.route.Options)
		if err == nil {
			// connection restored
			a.conn = conn
			fmt.Println("syslog: connection restored")
			return
		}

		i++
		fmt.Printf("syslog: reconnect attempt #%d\n", i+1)
		time.Sleep(1 * time.Second)
	}
}

func debugf(format string, v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("DEBUG "+format, v...)
	}
}

type SyslogMessage struct {
	*router.Message
}

func (m *SyslogMessage) Render(tmpl *template.Template) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := tmpl.Execute(buf, m)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *SyslogMessage) Priority() syslog.Priority {
	switch m.Message.Source {
	case "stdout":
		return syslog.LOG_USER | syslog.LOG_INFO
	case "stderr":
		return syslog.LOG_USER | syslog.LOG_ERR
	default:
		return syslog.LOG_DAEMON | syslog.LOG_INFO
	}
}

func (m *SyslogMessage) Hostname() string {
	return hostname
}

func (m *SyslogMessage) Timestamp() string {
	return m.Message.Time.Format(time.RFC3339)
}

func (m *SyslogMessage) ContainerName() string {
	return m.Message.Container.Name[1:]
}
