// ext-peer: the quic-go side of sakuya's runs of the two extensions the
// interop runner does not test, DATAGRAM (RFC 9221) and RESET_STREAM_AT
// (draft-ietf-quic-reliable-stream-reset). It takes the runner's
// environment (TESTCASE, REQUESTS, SSLKEYLOGFILE, QLOGDIR, /www, /certs,
// /downloads) as sakuya-interop-server and sakuya-interop-client do.
//
//	ext-peer server | ext-peer client
//
// TESTCASE=datagram: the server sends every datagram back; the client
// sends 50 datagrams of 8 to 1130 bytes to the server of the first URL and
// waits for each to come back, up to 5 rounds, writing
// /downloads/datagram.txt.
//
// TESTCASE=resetstreamat: hq-interop; the server writes the first half of
// each file, marks it reliable, writes 64 KiB more (or the rest) and
// resets the stream with code 0x52; the client saves what it read and
// writes how the answer ended to <file>.end.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/interop/utils"
)

const (
	alpn            = "hq-interop"
	resetCode       = 0x52
	datagrams       = 50
	largestDatagram = 1130
	rounds          = 5
	roundWait       = 2 * time.Second
	beyondReliable  = 64 * 1024
)

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ext-peer: "+format+"\n", args...)
}

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "server" && os.Args[1] != "client") {
		logf("usage: ext-peer server|client")
		os.Exit(2)
	}
	testcase := os.Getenv("TESTCASE")
	if testcase != "datagram" && testcase != "resetstreamat" {
		logf("unsupported test case %q", testcase)
		os.Exit(127)
	}
	keyLog, err := utils.GetSSLKeyLog()
	if err != nil {
		logf("key log: %v", err)
		os.Exit(1)
	}
	if keyLog != nil {
		defer keyLog.Close()
	}
	conf := &quic.Config{
		MaxIdleTimeout:                   30 * time.Second,
		EnableDatagrams:                  testcase == "datagram",
		EnableStreamResetPartialDelivery: testcase == "resetstreamat",
		Tracer:                           utils.NewQLOGConnectionTracer,
	}
	if os.Args[1] == "server" {
		err = serve(testcase, conf, keyLog)
	} else {
		err = fetch(testcase, conf, keyLog)
	}
	if err != nil {
		logf("%v", err)
		os.Exit(1)
	}
}

// ---- the server ----

func serve(testcase string, conf *quic.Config, keyLog io.Writer) error {
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		KeyLogWriter: keyLog,
		NextProtos:   []string{alpn},
	}
	ln, err := quic.ListenAddr(":443", tlsConf, conf)
	if err != nil {
		return err
	}
	logf("server listening on :443, test case %s", testcase)
	for n := 1; ; n++ {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go serveConn(n, testcase, conn)
	}
}

func serveConn(n int, testcase string, conn *quic.Conn) {
	state := conn.ConnectionState()
	logf("connection %d from %s: datagrams %+v, reset_stream_at %+v", n, conn.RemoteAddr(),
		state.SupportsDatagrams, state.SupportsStreamResetPartialDelivery)
	if testcase == "datagram" {
		go func() {
			echoed := 0
			for {
				b, err := conn.ReceiveDatagram(context.Background())
				if err != nil {
					logf("connection %d sent back %d datagrams; %v", n, echoed, err)
					return
				}
				if err := conn.SendDatagram(b); err != nil {
					logf("connection %d: a datagram of %d bytes is not sent back: %v", n, len(b), err)
					continue
				}
				echoed++
			}
		}()
	}
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			logf("connection %d takes no more streams: %v", n, err)
			return
		}
		go answer(n, testcase, str)
	}
}

func answer(n int, testcase string, str *quic.Stream) {
	request, err := io.ReadAll(io.LimitReader(str, 4096))
	if err != nil {
		logf("connection %d: a request cannot be read: %v", n, err)
		str.CancelWrite(0x10)
		return
	}
	path, ok := strings.CutPrefix(strings.TrimSpace(string(request)), "GET /")
	if !ok || strings.Contains(path, "..") {
		logf("connection %d: request %q refused", n, request)
		str.CancelWrite(0x10)
		return
	}
	content, err := os.ReadFile(filepath.Join("/www", path))
	if err != nil {
		logf("connection %d: %v", n, err)
		str.CancelWrite(0x10)
		return
	}
	if testcase != "resetstreamat" {
		if _, err := str.Write(content); err != nil {
			logf("connection %d: /%s cannot be sent: %v", n, path, err)
			return
		}
		str.Close()
		return
	}
	half := len(content) / 2
	end := min(len(content), half+beyondReliable)
	if _, err := str.Write(content[:half]); err != nil {
		logf("connection %d: /%s cannot be sent: %v", n, path, err)
		return
	}
	str.SetReliableBoundary()
	if _, err := str.Write(content[half:end]); err != nil {
		logf("connection %d: /%s cannot be sent: %v", n, path, err)
		return
	}
	str.CancelWrite(resetCode)
	logf("connection %d: /%s reset at %d after %d of %d bytes", n, path, half, end, len(content))
}

// ---- the client ----

func fetch(testcase string, conf *quic.Config, keyLog io.Writer) error {
	var urls []*url.URL
	for _, raw := range strings.Fields(os.Getenv("REQUESTS")) {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		urls = append(urls, u)
	}
	if len(urls) == 0 {
		return errors.New("REQUESTS is empty")
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       keyLog,
		NextProtos:         []string{alpn},
		ServerName:         urls[0].Hostname(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(urls[0].Hostname(), urls[0].Port()), tlsConf, conf)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "")
	state := conn.ConnectionState()
	logf("connected: datagrams %+v, reset_stream_at %+v", state.SupportsDatagrams,
		state.SupportsStreamResetPartialDelivery)
	if testcase == "datagram" {
		return exchangeDatagrams(conn)
	}
	errs := make(chan error, len(urls))
	for _, u := range urls {
		go func() { errs <- get(ctx, conn, u.Path) }()
	}
	var failed error
	for range urls {
		if err := <-errs; err != nil {
			failed = err
		}
	}
	return failed
}

func get(ctx context.Context, conn *quic.Conn, path string) error {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := str.Write([]byte("GET " + path + "\r\n")); err != nil {
		return err
	}
	str.Close()
	name := filepath.Join("/downloads", strings.TrimPrefix(path, "/"))
	data, err := io.ReadAll(str)
	if werr := os.WriteFile(name, data, 0o644); werr != nil {
		return werr
	}
	var end string
	var serr *quic.StreamError
	switch {
	case err == nil:
		end = fmt.Sprintf("fin received %d\n", len(data))
	case errors.As(err, &serr) && serr.Remote:
		end = fmt.Sprintf("reset %d received %d\n", serr.ErrorCode, len(data))
	default:
		return fmt.Errorf("%s after %d bytes: %w", path, len(data), err)
	}
	logf("%s: %s", path, strings.TrimSpace(end))
	return os.WriteFile(name+".end", []byte(end), 0o644)
}

func datagram(index, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint32(b, uint32(index))
	binary.BigEndian.PutUint32(b[4:], uint32(size))
	for i := 8; i < size; i++ {
		b[i] = byte(index)
	}
	return b
}

func exchangeDatagrams(conn *quic.Conn) error {
	sizes := make([]int, datagrams)
	for i := range sizes {
		sizes[i] = 8 + (largestDatagram-8)*i/(datagrams-1)
	}
	back := make([]bool, datagrams)
	missing := func() int {
		m := 0
		for _, b := range back {
			if !b {
				m++
			}
		}
		return m
	}
	received := make(chan []byte, 256)
	go func() {
		for {
			b, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				close(received)
				return
			}
			received <- b
		}
	}()
	mismatched, unexpected, round, refused := 0, 0, 0, 0
	ended := false
	for round < rounds && !ended && missing() > 0 {
		round++
		for i, size := range sizes {
			if back[i] {
				continue
			}
			if err := conn.SendDatagram(datagram(i, size)); err != nil {
				logf("datagram %d of %d bytes is refused: %v", i, size, err)
				refused++
			}
		}
		deadline := time.After(roundWait)
	wait:
		for missing() > 0 {
			select {
			case b, ok := <-received:
				if !ok {
					logf("the connection ended while datagrams were out")
					ended = true
					break wait
				}
				if len(b) < 8 {
					unexpected++
					continue
				}
				i := int(binary.BigEndian.Uint32(b))
				if i >= datagrams {
					unexpected++
				} else if bytes.Equal(b, datagram(i, sizes[i])) {
					back[i] = true
				} else {
					mismatched++
				}
			case <-deadline:
				break wait
			}
		}
		logf("datagram round %d: %d of %d came back", round, datagrams-missing(), datagrams)
	}
	var missed []int
	for i, b := range back {
		if !b {
			missed = append(missed, i)
		}
	}
	summary := fmt.Sprintf("sent %d largest %d rounds %d back %d missing %v mismatched %d unexpected %d refused %d\n",
		datagrams, largestDatagram, round, datagrams-len(missed), missed, mismatched, unexpected, refused)
	logf("datagrams: %s", strings.TrimSpace(summary))
	if err := os.WriteFile("/downloads/datagram.txt", []byte(summary), 0o644); err != nil {
		return err
	}
	if len(missed) > 0 || mismatched > 0 || unexpected > 0 {
		return errors.New("not every datagram came back as it was sent")
	}
	return nil
}
