package transport

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestQUICDatagramAndFragmentation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv, err := NewQuicTransport("127.0.0.1:0", "mesh-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	acceptCh := make(chan PeerConnection, 1)
	errCh := make(chan error, 1)
	go func() {
		pc, err := srv.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- pc
	}()

	cli, err := NewQuicTransport("127.0.0.1:0", "mesh-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	clientConn, err := cli.Dial(ctx, srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	var serverConn PeerConnection
	select {
	case serverConn = <-acceptCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("accept timeout")
	}
	defer serverConn.Close()

	payload := bytes.Repeat([]byte{0xAB}, 3500)
	if err := clientConn.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	got := recvUntilPacket(t, ctx, serverConn)
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled packet mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	reply := []byte("pong")
	if err := serverConn.SendDatagram(reply); err != nil {
		t.Fatal(err)
	}
	got = recvUntilPacket(t, ctx, clientConn)
	if !bytes.Equal(got, reply) {
		t.Fatalf("reply = %q", got)
	}
}

func recvUntilPacket(t *testing.T, ctx context.Context, pc PeerConnection) []byte {
	t.Helper()
	for {
		data, err := pc.RecvDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 {
			return data
		}
	}
}
