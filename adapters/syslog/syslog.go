package syslog

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/gliderlabs/logspout/cfg"
	"github.com/gliderlabs/logspout/router"
)

const (
	// Rfc5424Format is the modern syslog protocol format. https://tools.ietf.org/html/rfc5424
	Rfc5424Format Format = "rfc5424"
	// Rfc3164Format is the legacy BSD syslog protocol format. https://tools.ietf.org/html/rfc3164
	Rfc3164Format Format = "rfc3164"

	// TraditionalTCPFraming is the traditional LF framing of syslog messages on the wire
	TraditionalTCPFraming TCPFraming = "traditional"
	// OctetCountedTCPFraming prepends the size of each message before the message. https://tools.ietf.org/html/rfc6587#section-3.4.1
	OctetCountedTCPFraming TCPFraming = "octet-counted"

	defaultFormat     = Rfc5424Format
	defaultTCPFraming = TraditionalTCPFraming
	defaultRetryCount = 10
)

var (
	hostname string
)

// Format represents the RFC spec to use for syslog messages
type Format string

// TCPFraming represents the type of framing to use for syslog messages
type TCPFraming string

func init() {
	hostname, _ = os.Hostname()
	router.AdapterFactories.Register(NewSyslogAdapter, "syslog")
}

func debug(v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Println(v...)
	}
}

func getFormat() (Format, error) {
	switch s := cfg.GetEnvDefault("SYSLOG_FORMAT", string(defaultFormat)); s {
	case string(Rfc5424Format):
		return Rfc5424Format, nil
	case string(Rfc3164Format):
		return Rfc3164Format, nil
	default:
		return defaultFormat, fmt.Errorf("unknown SYSLOG_FORMAT value: %s", s)
	}
}

func getHostname() string {
	content, err := ioutil.ReadFile("/etc/host_hostname")
	if err == nil && len(content) > 0 {
		hostname = strings.TrimRight(string(content), "\r\n")
	} else {
		hostname = cfg.GetEnvDefault("SYSLOG_HOSTNAME", "{{.Container.Config.Hostname}}")
	}
	return hostname
}

func getFieldTemplates(route *router.Route) (*FieldTemplates, error) {
	var err error
	var s string
	var tmpl FieldTemplates

	s = cfg.GetEnvDefault("SYSLOG_PRIORITY", "{{.Priority}}")
	if tmpl.priority, err = template.New("priority").Parse(s); err != nil {
		return nil, err
	}
	debug("setting priority to:", s)

	s = cfg.GetEnvDefault("SYSLOG_TIMESTAMP", "{{.Timestamp}}")
	if tmpl.timestamp, err = template.New("timestamp").Parse(s); err != nil {
		return nil, err
	}
	debug("setting timestamp to:", s)

	s = getHostname()
	if tmpl.hostname, err = template.New("hostname").Parse(s); err != nil {
		return nil, err
	}
	debug("setting hostname to:", s)

	s = cfg.GetEnvDefault("SYSLOG_TAG", "{{.ContainerName}}"+route.Options["append_tag"])
	if tmpl.tag, err = template.New("tag").Parse(s); err != nil {
		return nil, err
	}
	debug("setting tag to:", s)

	s = cfg.GetEnvDefault("SYSLOG_PID", "{{.Container.State.Pid}}")
	if tmpl.pid, err = template.New("pid").Parse(s); err != nil {
		return nil, err
	}
	debug("setting pid to:", s)

	s = cfg.GetEnvDefault("SYSLOG_STRUCTURED_DATA", "")
	if route.Options["structured_data"] != "" {
		s = route.Options["structured_data"]
	}
	if s == "" {
		s = "-"
	} else {
		s = fmt.Sprintf("[%s]", s)
	}
	if tmpl.structuredData, err = template.New("structuredData").Parse(s); err != nil {
		return nil, err
	}
	debug("setting structuredData to:", s)

	s = cfg.GetEnvDefault("SYSLOG_DATA", "{{.Data}}")
	if tmpl.data, err = template.New("data").Parse(s); err != nil {
		return nil, err
	}
	debug("setting data to:", s)

	return &tmpl, nil
}

func getTCPFraming() (TCPFraming, error) {
	switch s := cfg.GetEnvDefault("SYSLOG_TCP_FRAMING", string(defaultTCPFraming)); s {
	case string(TraditionalTCPFraming):
		return TraditionalTCPFraming, nil
	case string(OctetCountedTCPFraming):
		return OctetCountedTCPFraming, nil
	default:
		return defaultTCPFraming, fmt.Errorf("unknown SYSLOG_TCP_FRAMING value: %s", s)
	}
}

func getRetryCount() uint {
	retryCountStr := cfg.GetEnvDefault("RETRY_COUNT", "")
	if retryCountStr != "" {
		retryCount, _ := strconv.Atoi(retryCountStr)
		return uint(retryCount)
	}
	return defaultRetryCount
}

func isTCPConnection(conn net.Conn) bool {
	switch conn.(type) {
	case *net.TCPConn:
		return true
	case *tls.Conn:
		return true
	default:
		return false
	}
}

// NewSyslogAdapter returnas a configured syslog.Adapter
func NewSyslogAdapter(route *router.Route) (router.LogAdapter, error) {
	transport, found := router.AdapterTransports.Lookup(route.AdapterTransport("udp"))
	if !found {
		return nil, errors.New("bad transport: " + route.Adapter)
	}
	conn, err := transport.Dial(route.Address, route.Options)
	if err != nil {
		return nil, err
	}

	format, err := getFormat()
	if err != nil {
		return nil, err
	}
	debug("setting format to:", format)

	tmpl, err := getFieldTemplates(route)
	if err != nil {
		return nil, err
	}

	connIsTCP := isTCPConnection(conn)
	debug("setting connIsTCP to:", connIsTCP)

	var tcpFraming TCPFraming
	if connIsTCP {
		if tcpFraming, err = getTCPFraming(); err != nil {
			return nil, err
		}
		debug("setting tcpFraming to:", tcpFraming)
	}

	retryCount := getRetryCount()
	debug("setting retryCount to:", retryCount)

	return &Adapter{
		route:      route,
		conn:       conn,
		connIsTCP:  connIsTCP,
		format:     format,
		tmpl:       tmpl,
		transport:  transport,
		tcpFraming: tcpFraming,
		retryCount: retryCount,
	}, nil
}

// FieldTemplates for rendering Syslog messages
type FieldTemplates struct {
	priority       *template.Template
	timestamp      *template.Template
	hostname       *template.Template
	tag            *template.Template
	pid            *template.Template
	structuredData *template.Template
	data           *template.Template
}

// Adapter streams log output to a connection in the Syslog format
type Adapter struct {
	conn       net.Conn
	connIsTCP  bool
	route      *router.Route
	format     Format
	tmpl       *FieldTemplates
	transport  router.AdapterTransport
	tcpFraming TCPFraming
	retryCount uint
}

// Stream sends log data to a connection
func (a *Adapter) Stream(logstream chan *router.Message) {
	// When this function returns, logspout exits.
	for message := range logstream {
		m := &Message{message}
		buf, err := m.Render(a.format, a.tmpl)
		if err != nil {
			log.Println("syslog (render):", err)
			return
		}

		if a.connIsTCP && a.tcpFraming == OctetCountedTCPFraming {
			buf = append([]byte(fmt.Sprintf("%d ", len(buf))), buf...)
		}

		// It seems SetWriteDeadline() does not have any effect anymore.
		// When we pause rsyslog, it takes 55s to be detected.
		a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err = a.conn.Write(buf); err != nil {
			fmt.Println("syslog:", err)
			if a.connIsTCP {
				if err = a.retry(buf, err); err != nil {
					log.Println("syslog retry err: %+v", err)
					return
				}
			}
		}
	}
}

func (a *Adapter) retry(buf []byte, err error) error {
	if opError, ok := err.(*net.OpError); ok {
		if (opError.Temporary() && !errors.Is(opError, syscall.ECONNRESET)) || opError.Timeout() {
			if err := a.resend(buf); err == nil {
				return nil
			}
		}
	}

	// reconnect forever
	a.reconnect()

	return a.resend(buf)
}

func (a *Adapter) resend(buf []byte) error {
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

func (a *Adapter) reconnect() error {
	log.Println("syslog: reconnecting every 2s")

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
		if i == 150 {
			log.Println("syslog: no luck to reconnect for the past 5m")
			i = 0
		}
		time.Sleep(2 * time.Second)
	}
}

func debugf(format string, v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("DEBUG "+format, v...)
	}
}

// Message extends router.Message for the syslog standard
type Message struct {
	*router.Message
}

// Render transforms the log message using the Syslog template
func (m *Message) Render(format Format, tmpl *FieldTemplates) ([]byte, error) {
	priority := new(bytes.Buffer)
	if err := tmpl.priority.Execute(priority, m); err != nil {
		return nil, err
	}

	timestamp := new(bytes.Buffer)
	if err := tmpl.timestamp.Execute(timestamp, m); err != nil {
		return nil, err
	}

	hostname := new(bytes.Buffer)
	if err := tmpl.hostname.Execute(hostname, m); err != nil {
		return nil, err
	}

	tag := new(bytes.Buffer)
	if err := tmpl.tag.Execute(tag, m); err != nil {
		return nil, err
	}

	pid := new(bytes.Buffer)
	if err := tmpl.pid.Execute(pid, m); err != nil {
		return nil, err
	}

	structuredData := new(bytes.Buffer)
	if err := tmpl.structuredData.Execute(structuredData, m); err != nil {
		return nil, err
	}

	data := new(bytes.Buffer)
	if err := tmpl.data.Execute(data, m); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	switch format {
	case Rfc5424Format:
		// notes from RFC:
		// - there is no upper limit for the entire message and depends on the transport in use
		// - the HOSTNAME field must not exceed 255 characters
		// - the TAG field must not exceed 48 characters
		// - the PROCID field must not exceed 128 characters
		fmt.Fprintf(buf, "<%s>1 %s %.255s %.48s %.128s - %s %s\n",
			priority, timestamp, hostname, tag, pid, structuredData, data,
		)
	case Rfc3164Format:
		// notes from RFC:
		// - the entire message must be <= 1024 bytes
		// - the TAG field must not exceed 32 characters
		fmt.Fprintf(buf, "<%s>%s %s %.32s[%s]: %s\n",
			priority, timestamp, hostname, tag, pid, data,
		)
	}

	return buf.Bytes(), nil
}

// Priority returns a syslog.Priority based on the message source
func (m *Message) Priority() syslog.Priority {
	switch m.Message.Source {
	case "stdout":
		return syslog.LOG_USER | syslog.LOG_INFO
	case "stderr":
		return syslog.LOG_USER | syslog.LOG_ERR
	default:
		return syslog.LOG_DAEMON | syslog.LOG_INFO
	}
}

// Hostname returns the os hostname
func (m *Message) Hostname() string {
	return hostname
}

// Timestamp returns the message's syslog formatted timestamp
func (m *Message) Timestamp() string {
	return m.Message.Time.Format(time.RFC3339)
}

// ContainerName returns the message's container name
func (m *Message) ContainerName() string {
	return m.Message.Container.Name[1:]
}

// ContainerNameSplitN returns the message's container name sliced at most "n" times using "sep"
func (m *Message) ContainerNameSplitN(sep string, n int) []string {
	return strings.SplitN(m.ContainerName(), sep, n)
}
