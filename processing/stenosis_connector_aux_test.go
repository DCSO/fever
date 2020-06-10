package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/DCSO/fever/stenosis/api"
	"github.com/DCSO/fever/stenosis/task"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	mockGRPCServerMethNewMockGRPCServer = "newMockGRPCServer"
	mockGRPCServerMethAlive             = "Alive"
	mockGRPCServerMethListenAndServe    = "ListenAndServe"
	mockGRPCServerMethQuery             = "Query"
)

type mockGRPCServerOptionFunc func(*mockGRPCServer)

type mockGRPCServerTokenGenFunc func(*task.Query) string

func mockGRPCServerDefaultTokenGen(query *task.Query) string {
	switch query.GetType() {
	case task.QueryType_FLOW_PARAM:
		fp := query.GetFlowParam()
		if fp == nil {
			return ""
		}
		return fp.GetNetwork() + fp.GetSrcHostPort() + fp.GetDstHostPort()
	case task.QueryType_MOCK_QUERY:
		mq := query.GetMockQuery()
		if mq == nil {
			return ""
		}
		return mq.GetMock()
	default:
		return ""
	}
}

func mockGRPCServerTokenGenerateOption(tokenGen mockGRPCServerTokenGenFunc) mockGRPCServerOptionFunc {
	return func(m *mockGRPCServer) {
		m.tokenGen = tokenGen
	}
}

type mockGRPCServer struct {
	tokenGen mockGRPCServerTokenGenFunc
	failWith map[string]error
	server   *grpc.Server
	addr     string
	mtx      sync.RWMutex
}

func newMockGRPCServer(options ...mockGRPCServerOptionFunc) (*mockGRPCServer, error) {
	m := &mockGRPCServer{
		failWith: make(map[string]error),
		tokenGen: mockGRPCServerDefaultTokenGen,
	}
	for _, opt := range options {
		opt(m)
	}
	if err, ok := m.failWith[mockGRPCServerMethNewMockGRPCServer]; ok {
		return nil, err
	}
	m.server = grpc.NewServer()
	api.RegisterStenosisServiceQueryServer(m.server, m)
	return m, nil
}

func (m *mockGRPCServer) Close() {
	if m.server != nil {
		m.server.GracefulStop()
	}
}

func (m *mockGRPCServer) ListenAndServe() error {
	if err, ok := m.failWith[mockGRPCServerMethListenAndServe]; ok {
		return err
	}
	tmpFolder, err := ioutil.TempDir("", "mockGRPCServer_")
	if err != nil {
		return err
	}
	defer func() {
		if tmpFolder != "" {
			_ = os.RemoveAll(tmpFolder)
		}
	}()
	logrus.Debugf("using temporary folder in %s", tmpFolder)
	sf := filepath.Join(tmpFolder, "stenosis_connector.socket")
	ln, err := net.Listen("unix", sf)
	if err != nil {
		return err
	}
	m.mtx.Lock()
	m.addr = sf
	m.mtx.Unlock()
	if dsln, ok := ln.(*net.UnixListener); ok {
		dsln.SetUnlinkOnClose(true)
	}
	defer ln.Close()
	return m.server.Serve(ln)
}

func (m *mockGRPCServer) Alive(ctx context.Context, req *api.AliveRequest) (*api.AliveResponse, error) {
	if err, ok := m.failWith[mockGRPCServerMethAlive]; ok {
		return nil, err
	}
	return &api.AliveResponse{Id: req.GetId(), Ok: http.StatusText(http.StatusOK)}, nil
}

func (m *mockGRPCServer) Query(ctx context.Context, req *task.Query) (*api.QueryResponse, error) {
	if err, ok := m.failWith[mockGRPCServerMethQuery]; ok {
		return nil, err
	}
	return &api.QueryResponse{Token: m.tokenGen(req)}, nil
}

func (m *mockGRPCServer) Addr() string {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return fmt.Sprintf("unix://%s", m.addr)
}
