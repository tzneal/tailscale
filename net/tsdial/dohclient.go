// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdial

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// dohConn is a net.PacketConn suitable for returning from
// net.Dialer.Dial to send DNS queries over PeerAPI to exit nodes'
// ExitDNS DoH proxy service.
type dohConn struct {
	ctx     context.Context
	baseURL string
	hc      *http.Client // if nil, default is used

	rbuf bytes.Buffer
}

var (
	_ net.Conn       = (*dohConn)(nil)
	_ net.PacketConn = (*dohConn)(nil) // be a PacketConn to change net.Resolver semantics
)

func (*dohConn) Close() error                       { return nil }
func (*dohConn) LocalAddr() net.Addr                { return todoAddr{} }
func (*dohConn) RemoteAddr() net.Addr               { return todoAddr{} }
func (*dohConn) SetDeadline(t time.Time) error      { return nil }
func (*dohConn) SetReadDeadline(t time.Time) error  { return nil }
func (*dohConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *dohConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *dohConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, todoAddr{}, err
}

func (c *dohConn) Read(p []byte) (n int, err error) {
	return c.rbuf.Read(p)
}

func (c *dohConn) Write(packet []byte) (n int, err error) {
	req, err := http.NewRequestWithContext(c.ctx, "POST", c.baseURL, bytes.NewReader(packet))
	if err != nil {
		return 0, err
	}
	const dohType = "application/dns-message"
	req.Header.Set("Content-Type", dohType)
	hc := c.hc
	if hc == nil {
		hc = http.DefaultClient
	}
	hres, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer hres.Body.Close()
	if hres.StatusCode != 200 {
		return 0, errors.New(hres.Status)
	}
	if ct := hres.Header.Get("Content-Type"); ct != dohType {
		return 0, fmt.Errorf("unexpected response Content-Type %q", ct)
	}
	_, err = io.Copy(&c.rbuf, hres.Body)
	if err != nil {
		return 0, err
	}
	return len(packet), nil
}

type todoAddr struct{}

func (todoAddr) Network() string { return "unused" }
func (todoAddr) String() string  { return "unused-todoAddr" }
