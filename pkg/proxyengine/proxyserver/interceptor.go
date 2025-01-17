/*
Copyright 2023 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxyserver

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apiserver/pkg/util/flushwriter"
	"k8s.io/apiserver/pkg/util/wsstream"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/pkg/utils"
)

var (
	SupportedHeaders = []string{utils.RavenProxyHostHeaderKey, utils.RavenProxyUserHeaderKey}
	IOReaderPool     sync.Pool
)

const HTTPCloseErr = "use of closed network connection"

// newBufioReader retrieves a cached Reader from the pool if the pool is not empty,
// otherwise creates a new one
func newBufioReader(r io.Reader) *bufio.Reader {
	if v := IOReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	return bufio.NewReader(r)
}

// putBufioReader puts the Reader to the pool.
func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	IOReaderPool.Put(br)
}

type Connect interface {
	Connect(r *http.Request) (net.Conn, error)
}

type Interceptor struct {
	dial func(address string, header http.Header, isTLS bool) (net.Conn, error)
}

func NewInterceptor(udsFile string, cfg *tls.Config) http.Handler {
	if cfg == nil {
		return nil
	}
	dial := func(address string, header http.Header, isTLS bool) (net.Conn, error) {
		var conn net.Conn
		var err error
		switch header.Get(utils.RavenProxyServerForwardModeHeaderKey) {
		case utils.RavenProxyServerForwardLocalMode:
			if address == "" {
				return nil, fmt.Errorf("failed to connect, address is empty")
			}
			conn, err = net.Dial("tcp", address)
			if err != nil {
				return nil, fmt.Errorf("failed to dial server %s, error %s", address, err.Error())
			}

		case utils.RavenProxyServerForwardRemoteMode:
			if udsFile == "" {
				return nil, fmt.Errorf("failed to connect, uds file is empty")
			}
			conn, err = net.Dial("unix", udsFile)
			if err != nil {
				return nil, fmt.Errorf("failed to dial proxy %s, error %s", udsFile, err.Error())
			}
			var connectHeaders string
			for _, val := range SupportedHeaders {
				if v := header.Get(val); len(v) != 0 {
					connectHeaders = fmt.Sprintf("%s\r\n%s:%s", connectHeaders, val, v)
				}
			}
			_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: localhost%s\r\n\r\n", address, connectHeaders)
			if err != nil {
				return nil, fmt.Errorf("failed format connect header, error %s", err.Error())
			}
			br := newBufioReader(conn)
			defer putBufioReader(br)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("reading HTTP response from CONNECT to %s failed %s", address, err.Error())
			}
			if resp.StatusCode != 200 {
				conn.Close()
				return nil, fmt.Errorf("proxy err while dialing %s, code %d: %v", address, resp.StatusCode, resp.Status)
			}
		default:
			return nil, fmt.Errorf("unrecognize the proxy forwarding mode")
		}
		if isTLS {
			cfg.InsecureSkipVerify = true
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("fail to setup TLS handshake to %s: error %s", address, err.Error())
			}
			return tlsConn, nil
		}
		return conn, nil
	}
	return &Interceptor{dial: dial}
}

func (c *Interceptor) Connect(r *http.Request) (net.Conn, error) {
	return c.dial(r.Host, r.Header, r.TLS != nil)
}

func (c *Interceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := c.Connect(r)
	if err != nil {
		logAndHTTPError(w, http.StatusServiceUnavailable, "failed to setup the proxy for %s, error %s", r.Host, err)
		return
	}
	defer conn.Close()

	err = r.Write(conn)
	if err != nil {
		logAndHTTPError(w, http.StatusServiceUnavailable, "failed to write request to conn, err %s", err.Error())
		return
	}

	if httpstream.IsUpgradeRequest(r) {
		serveUpgradeRequest(conn, w, r)
	} else {
		serveRequest(conn, w, r)
	}
}

// serverRequest serves the normal requests, e.g., kubectl logs
func serveRequest(conn net.Conn, w http.ResponseWriter, r *http.Request) {
	klog.Infof("interceptor: start serving request %s with header: host %s, proxy mode: %s",
		r.URL.String(), r.Header[utils.RavenProxyHostHeaderKey], r.Header[utils.RavenProxyServerForwardModeHeaderKey])
	defer klog.Infof("interceptor: stop serving request %s with header: host %s, proxy mode: %s",
		r.URL.String(), r.Header[utils.RavenProxyHostHeaderKey], r.Header[utils.RavenProxyServerForwardModeHeaderKey])
	br := newBufioReader(conn)
	defer putBufioReader(br)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		logAndHTTPError(w, http.StatusServiceUnavailable, "fail to read response from the conn: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	if wsstream.IsWebSocketRequest(r) {
		wsReader := wsstream.NewReader(resp.Body, true, wsstream.NewDefaultReaderProtocols())
		if err = wsReader.Copy(w, r); err != nil {
			klog.ErrorS(err, "error encountered while streaming results via websocket")
		}
		return
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	writer := w.(io.Writer)
	if isChunked(resp) {
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func(r *http.Request, conn net.Conn, stopCh chan struct{}) {
			ctx := r.Context()
			select {
			case <-stopCh:
				klog.Infof("chunked request(%s) normally exit", r.URL.String())
			case <-ctx.Done():
				klog.Infof("chunked request(%s) to agent(%s) closed by cloud client, %v", r.URL.String(),
					r.Header.Get(utils.RavenProxyHostHeaderKey), ctx.Err())
				conn.Close()
			}
		}(r, conn, stopCh)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		writer = flushwriter.Wrap(w)
	}
	_, err = io.Copy(writer, resp.Body)
	if err != nil && !isHTTPCloseError(err) {
		klog.ErrorS(err, "failed to copy response from proxy server to the frontend")
	}
}

func serveUpgradeRequest(conn net.Conn, w http.ResponseWriter, r *http.Request) {
	klog.Infof("interceptor: start serving streaming request %s with header: host %s, proxy mode: %s",
		r.URL.String(), r.Header[utils.RavenProxyHostHeaderKey], r.Header[utils.RavenProxyServerForwardModeHeaderKey])
	defer klog.Infof("interceptor: stop serving streaming request %s with header: host %s, proxy mode: %s",
		r.URL.String(), r.Header[utils.RavenProxyHostHeaderKey], r.Header[utils.RavenProxyServerForwardModeHeaderKey])

	resp, rawResp, err := getResponse(conn)
	if err != nil {
		logAndHTTPError(w, http.StatusServiceUnavailable, "proxy connection error %s", err.Error())
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logAndHTTPError(w, http.StatusServiceUnavailable, "can't assert response to http.Hijacker")
		return
	}
	frontend, _, err := hijacker.Hijack()
	if err != nil {
		logAndHTTPError(w, http.StatusServiceUnavailable, "fail to hijack response: %s", err.Error())
		return
	}
	defer frontend.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		deadline := time.Now().Add(10 * time.Second)
		if err = conn.SetReadDeadline(deadline); err != nil {
			klog.Errorf("failed set proxy connect deadline, error %s", err.Error())
		}
		if err = frontend.SetReadDeadline(deadline); err != nil {
			klog.Errorf("failed set frontend connect deadline, error %s", err.Error())
		}
		err = resp.Write(frontend)
		if err != nil && !isHTTPCloseError(err) {
			klog.Errorf("error proxying un-upgrade response from proxy channel to frontend: %s", err.Error())
		}
		return
	}

	if len(rawResp) > 0 {
		if _, err = frontend.Write(rawResp); err != nil {
			klog.Errorf("error proxying response bytes from tunnel to client: %s", err.Error())
		}
	}

	readerComplete, writerComplete := make(chan struct{}), make(chan struct{})
	go func() {
		_, err = io.Copy(conn, frontend)
		if err != nil && !isHTTPCloseError(err) {
			klog.Errorf("error proxying data from frontend to proxy channel: %s", err.Error())
		}
		close(writerComplete)
	}()

	go func() {
		_, err = io.Copy(frontend, conn)
		if err != nil && !isHTTPCloseError(err) {
			klog.Errorf("error proxying data from proxy channel to frontend: %s", err.Error())
		}
		close(readerComplete)
	}()

	select {
	case <-writerComplete:
	case <-readerComplete:
	}
}

func logAndHTTPError(w http.ResponseWriter, errCode int, format string, i ...interface{}) {
	errMsg := fmt.Sprintf(format, i...)
	klog.Error(errMsg)
	http.Error(w, errMsg, errCode)
}

func copyHeader(dst, src http.Header) {
	for key, val := range src {
		for _, v := range val {
			dst.Add(key, v)
		}
	}
}

// isChunked verify the specified response is chunked stream or not.
func isChunked(resp *http.Response) bool {
	for _, h := range resp.Header[http.CanonicalHeaderKey("Transfer-Encoding")] {
		if strings.Contains(strings.ToLower(h), strings.ToLower("chunked")) {
			return true
		}
	}

	for _, te := range resp.TransferEncoding {
		if strings.Contains(strings.ToLower(te), strings.ToLower("chunked")) {
			return true
		}
	}
	return false
}

func isHTTPCloseError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), HTTPCloseErr)
}

// getResponseCode reads a http response from the given reader, returns the response,
// the bytes read from the reader, and any error encountered
func getResponse(r io.Reader) (*http.Response, []byte, error) {
	rawResponse := bytes.NewBuffer(make([]byte, 0, 256))
	// Save the bytes read while reading the response headers into the rawResponse buffer
	br := newBufioReader(io.TeeReader(r, rawResponse))
	defer putBufioReader(br)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, err
	}
	// return the http response and the raw bytes consumed from the reader in the process
	return resp, rawResponse.Bytes(), nil
}
