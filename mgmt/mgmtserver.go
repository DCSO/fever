package mgmt

// DCSO FEVER
// Copyright (c) 2021, DCSO GmbH

import (
	context "context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/DCSO/bloom"
	"github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

const (
	permSocketPath = 0750
)

type mgmtServer struct {
	UnimplementedMgmtServiceServer
	ctx     context.Context
	Logger  *logrus.Entry
	grpcSrv *grpc.Server
	cfg     GRPCEndpointConfig
	state   *State
}

// NewMgmtServer returns a new mamagement server instance registered with gRPC.
func NewMgmtServer(parent context.Context, cfg GRPCEndpointConfig, state *State) (Server, error) {
	srv := &mgmtServer{
		ctx:   parent,
		cfg:   cfg,
		state: state,
		Logger: logrus.StandardLogger().WithFields(logrus.Fields{
			"domain": "mgmt",
		}),
	}
	srv.grpcSrv = grpc.NewServer(cfg.ServerOptions...)
	RegisterMgmtServiceServer(srv.grpcSrv, srv)

	return srv, nil
}

// Stop stops the mgmtServer.
func (srv *mgmtServer) Stop() {
	srv.grpcSrv.GracefulStop()
}

// ListenAndServe starts the mgmtServer, accepting connections on the given
// communication channel.
func (srv *mgmtServer) ListenAndServe() (err error) {
	err = errors.New("ListenAndServe() can only be called once")

	var ln net.Listener

	if ln, err = net.Listen(srv.cfg.Network, srv.cfg.ListenerAddress); err != nil {
		srv.Logger.WithError(err).WithFields(logrus.Fields{
			"network": srv.cfg.Network,
			"address": srv.cfg.ListenerAddress,
		}).Error("setting up mgmt endpoint")
		return
	}
	defer ln.Close()

	if dsln, ok := ln.(*net.UnixListener); ok {
		if err = os.MkdirAll(filepath.Dir(srv.cfg.ListenerAddress), permSocketPath); err != nil {
			srv.Logger.WithError(err).WithFields(logrus.Fields{
				"path":      filepath.Dir(srv.cfg.ListenerAddress),
				"perm_path": permSocketPath,
			}).Error("unable to create path")
			return
		}
		dsln.SetUnlinkOnClose(true)
	}

	srv.Logger.Info("gRPC mgmt service listening ...")
	err = srv.grpcSrv.Serve(ln)
	srv.Logger.Info("gRPC mgmt service stopped")
	return err
}

//
// MgmtServiceServer interface
//

// BloomInfo implements the function to return internal status information about
// the Bloom filter currently loaded in the FEVER instance.
func (srv *mgmtServer) BloomInfo(ctx context.Context, _req *emptypb.Empty) (*MgmtBloomInfoResponse, error) {
	srv.Logger.Debug("responding to BloomInfo")

	var resp *MgmtBloomInfoResponse
	hasBloom := (srv.state.BloomHandler != nil)
	if hasBloom {
		resp = &MgmtBloomInfoResponse{
			HasBloom:  true,
			Capacity:  srv.state.BloomHandler.IocBloom.MaxNumElements(),
			Elements:  srv.state.BloomHandler.IocBloom.N,
			Bits:      srv.state.BloomHandler.IocBloom.NumBits(),
			Fpprob:    srv.state.BloomHandler.IocBloom.FalsePositiveProb(),
			Hashfuncs: srv.state.BloomHandler.IocBloom.NumHashFuncs(),
		}
	} else {
		resp = &MgmtBloomInfoResponse{
			HasBloom: false,
		}
	}
	return resp, nil
}

// BloomAdd implements the function to add items from an incoming stream to the
// Bloom filter currently loaded in the FEVER instance.
func (srv *mgmtServer) BloomAdd(stream MgmtService_BloomAddServer) error {
	srv.Logger.Debug("responding to BloomAdd")

	hasBloom := (srv.state.BloomHandler != nil)
	if !hasBloom {
		return stream.SendAndClose(&MgmtBloomAddResponse{Added: 0})
	}
	i := uint64(0)
	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return stream.SendAndClose(&MgmtBloomAddResponse{Added: i})
			}
			return status.Error(codes.InvalidArgument, err.Error())
		}
		srv.state.BloomHandler.IocBloom.Add([]byte(req.GetIoc()))
		i++
	}
}

// BloomSave implements the function to serialize the Bloom filter currently
// loaded in the FEVER instance to disk.
func (srv *mgmtServer) BloomSave(ctx context.Context, _req *emptypb.Empty) (*emptypb.Empty, error) {
	srv.Logger.Debug("responding to BloomSave")

	hasBloom := (srv.state.BloomHandler != nil)
	if !hasBloom {
		return &emptypb.Empty{}, nil
	}
	if srv.state.BloomHandler.BloomFilename == "" {
		return &emptypb.Empty{}, fmt.Errorf("filter was not created from file, cannot be saved")
	}
	err := bloom.WriteFilter(srv.state.BloomHandler.IocBloom,
		srv.state.BloomHandler.BloomFilename,
		srv.state.BloomHandler.BloomFileIsCompressed)
	if err != nil {
		return &emptypb.Empty{}, err
	}

	return &emptypb.Empty{}, nil
}

// BloomReload implements the function to reload the Bloom filter currently
// loaded in the FEVER instance from disk.
func (srv *mgmtServer) BloomReload(ctx context.Context, _req *emptypb.Empty) (*emptypb.Empty, error) {
	srv.Logger.Debug("responding to BloomReload")

	hasBloom := (srv.state.BloomHandler != nil)
	if !hasBloom {
		return &emptypb.Empty{}, nil
	}
	err := srv.state.BloomHandler.Reload()
	if err != nil {
		return &emptypb.Empty{}, err
	}

	return &emptypb.Empty{}, nil
}

// Alive implements a simple echo command.
func (srv *mgmtServer) Alive(ctx context.Context, req *MgmtAliveRequest) (*MgmtAliveResponse, error) {
	return &MgmtAliveResponse{Echo: req.GetAlive()}, nil
}
