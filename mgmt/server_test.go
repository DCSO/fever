package mgmt

// DCSO FEVER
// Copyright (c) 2021, DCSO GmbH

import (
	context "context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/DCSO/bloom"
	"github.com/DCSO/fever/processing"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	grpc "google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var (
	mgmtCfg = GRPCEndpointConfig{
		EndpointConfig: EndpointConfig{
			Network:         "unix",
			ListenerAddress: "../tmp/test-fever-mgmt.socket",
			TLSDisable:      true,
		},
		DialOptions: []grpc.DialOption{grpc.WithInsecure()},
	}
)

func TestMain(m *testing.M) {
	logrus.SetLevel(logrus.TraceLevel)
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eg, ectx := errgroup.WithContext(cctx)

	if _, err := os.Stat("../tmp"); os.IsNotExist(err) {
		err := os.Mkdir("../tmp", os.ModePerm)
		if err != nil {
			logrus.Fatal(err)
		}
	}

	bf := bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("foo"))

	bfFile, err := ioutil.TempFile("", "example")
	if err != nil {
		logrus.Fatal(err)
	}
	defer os.Remove(bfFile.Name())
	bf.Write(bfFile)
	bfFile.Close()

	bh, err := processing.MakeBloomHandlerFromFile(bfFile.Name(), false, nil,
		nil, "alert", []string{})
	if err != nil {
		logrus.Fatal(err)
	}

	msrv, err := NewMgmtServer(ectx, mgmtCfg, &State{
		BloomHandler: bh,
	})
	if err != nil {
		logrus.Fatal(err)
	}
	eg.Go(func() error {
		if err := msrv.ListenAndServe(); err != nil {
			logrus.WithError(err).Error("gRPC server failed")
			return err
		}
		return nil
	})
	time.Sleep(100 * time.Millisecond)

	defer func() {
		cancel()
	}()
	if rc := m.Run(); rc != 0 {
		cancel()
		msrv.Stop()
		logrus.Warnf("test failed with %d", rc)
		os.Exit(rc)
	}
	cancel()
	msrv.Stop()
}

func TestAlive(t *testing.T) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	conn, err := grpc.Dial(mgmtCfg.Network+":"+mgmtCfg.ListenerAddress, mgmtCfg.DialOptions...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	clt := NewMgmtServiceClient(conn)
	got, err := clt.Alive(context.TODO(), &MgmtAliveRequest{Alive: "TestAlive"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetEcho() != "TestAlive" {
		t.Errorf("Alive(): %v, want %v", got.GetEcho(), "TestAlive")
	}
}

func TestBloomInfo(t *testing.T) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	conn, err := grpc.Dial(mgmtCfg.Network+":"+mgmtCfg.ListenerAddress, mgmtCfg.DialOptions...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	clt := NewMgmtServiceClient(conn)
	got, err := clt.BloomInfo(context.TODO(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetCapacity() != 100000 {
		t.Errorf("BloomInfo(): %v, want %v", got.GetCapacity(), 100000)
	}
	if got.GetFpprob() != 0.0000001 {
		t.Errorf("BloomInfo(): %v, want %v", got.GetFpprob(), 0.0000001)
	}
	if got.GetElements() != 1 {
		t.Errorf("BloomInfo(): %v, want %v", got.GetElements(), 1)
	}
	if got.GetHashfuncs() != 24 {
		t.Errorf("BloomInfo(): %v, want %v", got.GetHashfuncs(), 24)
	}
	if got.GetBits() != 3354770 {
		t.Errorf("BloomInfo(): %v, want %v", got.GetBits(), 3354770)
	}
}

func TestBloomSave(t *testing.T) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	conn, err := grpc.Dial(mgmtCfg.Network+":"+mgmtCfg.ListenerAddress, mgmtCfg.DialOptions...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	clt := NewMgmtServiceClient(conn)
	_, err = clt.BloomSave(context.TODO(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}

}

func TestBloomReload(t *testing.T) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	conn, err := grpc.Dial(mgmtCfg.Network+":"+mgmtCfg.ListenerAddress, mgmtCfg.DialOptions...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	clt := NewMgmtServiceClient(conn)
	_, err = clt.BloomReload(context.TODO(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBloomAdd(t *testing.T) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	conn, err := grpc.Dial(mgmtCfg.Network+":"+mgmtCfg.ListenerAddress, mgmtCfg.DialOptions...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	clt := NewMgmtServiceClient(conn)
	got, err := clt.BloomInfo(context.TODO(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetElements() != 1 {
		t.Errorf("BloomAdd(): %v, want %v", got.GetElements(), 1)
	}

	stream, err := clt.BloomAdd(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"a", "b", "c"} {
		if err := stream.Send(&MgmtBloomAddRequest{Ioc: part}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetAdded() != 3 {
		t.Fatalf("wanted 3, got %d", resp.GetAdded())
	}

	got, err = clt.BloomInfo(context.TODO(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetElements() != 4 {
		t.Errorf("BloomAdd(): %v, want %v", got.GetElements(), 4)
	}
}
