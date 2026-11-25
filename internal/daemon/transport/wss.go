package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/acktier/acktier/pkg/types"
)

const wsPath = "/acktier-ws"

type wsPeerConn struct {
	addr string
	conn *websocket.Conn
}

// WSSDriver transports wire frames as binary WebSocket messages over TLS 1.3 (HTTPS/WSS),
// enabling traversal through strict corporate HTTP/443 firewalls and reverse proxies.
type WSSDriver struct {
	tlsLn      net.Listener
	httpSrv    *http.Server
	httpClient *http.Client
	onRecv     PacketHandler

	mu        sync.RWMutex
	conns     map[string]*wsPeerConn
	closeOnce sync.Once
	closed    chan struct{}
}

func NewWSSDriver(rawLn net.Listener, dial StreamDialFunc, onRecv PacketHandler) (*WSSDriver, error) {
	serverTLS, err := GenerateEphemeralTLSConfig(alpnWSS)
	if err != nil {
		return nil, err
	}
	clientTLS, err := GenerateEphemeralTLSConfig(alpnWSS)
	if err != nil {
		return nil, err
	}
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}

	tr := &http.Transport{
		DialContext:     dial,
		TLSClientConfig: clientTLS,
	}
	wd := &WSSDriver{
		httpClient: &http.Client{Transport: tr},
		onRecv:     onRecv,
		conns:      make(map[string]*wsPeerConn),
		closed:     make(chan struct{}),
	}

	if rawLn != nil {
		wd.tlsLn = tls.NewListener(rawLn, serverTLS)
		mux := http.NewServeMux()
		mux.HandleFunc(wsPath, wd.handleWSUpgrade)
		wd.httpSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 8 * time.Second,
		}
		go func() {
			_ = wd.httpSrv.Serve(wd.tlsLn)
		}()
	}
	return wd, nil
}

func (d *WSSDriver) Proto() types.TransportProto { return types.ProtoWSS }

func (d *WSSDriver) LocalAddr() string {
	if d.tlsLn == nil || d.tlsLn.Addr() == nil {
		return ""
	}
	return d.tlsLn.Addr().String()
}

func (d *WSSDriver) Send(ctx context.Context, addr string, pkt []byte) error {
	d.mu.RLock()
	existing := d.conns[addr]
	d.mu.RUnlock()

	if existing != nil {
		writeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := existing.conn.Write(writeCtx, websocket.MessageBinary, pkt)
		cancel()
		if err == nil {
			return nil
		}
		d.removeConn(addr, existing)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	wsURL := fmt.Sprintf("wss://%s%s", addr, wsPath)
	c, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPClient: d.httpClient,
	})
	cancel()
	if err != nil {
		return err
	}
	c.SetReadLimit(65536)

	wc := d.registerConn(addr, c)
	writeCtx, wCancel := context.WithTimeout(ctx, 4*time.Second)
	err = wc.conn.Write(writeCtx, websocket.MessageBinary, pkt)
	wCancel()
	if err != nil {
		d.removeConn(addr, wc)
		return err
	}
	return nil
}

func (d *WSSDriver) handleWSUpgrade(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	c.SetReadLimit(65536)
	d.registerConn(r.RemoteAddr, c)
}

func (d *WSSDriver) registerConn(addr string, c *websocket.Conn) *wsPeerConn {
	wc := &wsPeerConn{addr: addr, conn: c}
	d.mu.Lock()
	if old, ok := d.conns[addr]; ok {
		_ = old.conn.CloseNow()
	}
	d.conns[addr] = wc
	d.mu.Unlock()

	go d.readLoop(wc)
	return wc
}

func (d *WSSDriver) readLoop(wc *wsPeerConn) {
	defer d.removeConn(wc.addr, wc)
	for {
		msgType, data, err := wc.conn.Read(context.Background())
		if err != nil {
			return
		}
		if msgType == websocket.MessageBinary && d.onRecv != nil && len(data) > 0 {
			d.onRecv(data, types.Endpoint{
				Proto: types.ProtoWSS,
				Addr:  wc.addr,
			})
		}
	}
}

func (d *WSSDriver) removeConn(addr string, wc *wsPeerConn) {
	_ = wc.conn.CloseNow()
	d.mu.Lock()
	if cur, ok := d.conns[addr]; ok && cur == wc {
		delete(d.conns, addr)
	}
	d.mu.Unlock()
}

// ResetConnections terminates all active WebSocket peer connections while keeping the TLS listener bound.
func (d *WSSDriver) ResetConnections() {
	d.mu.Lock()
	for k, wc := range d.conns {
		_ = wc.conn.CloseNow()
		delete(d.conns, k)
	}
	d.mu.Unlock()
}

func (d *WSSDriver) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		if d.httpSrv != nil {
			_ = d.httpSrv.Close()
		}
		if d.tlsLn != nil {
			_ = d.tlsLn.Close()
		}
		d.mu.Lock()
		for k, wc := range d.conns {
			_ = wc.conn.CloseNow()
			delete(d.conns, k)
		}
		d.mu.Unlock()
	})
	return nil
}
