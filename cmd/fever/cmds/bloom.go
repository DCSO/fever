package cmd

// DCSO FEVER
// Copyright (c) 2021, DCSO GmbH

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/DCSO/fever/mgmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	clt  mgmt.MgmtServiceClient
	conn *grpc.ClientConn
)

func bloomAdd(cmd *cobra.Command, args []string) {
	stream, err := clt.BloomAdd(context.TODO())
	if err != nil {
		logrus.Fatal(err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if err := stream.Send(&mgmt.MgmtBloomAddRequest{
			Ioc: scanner.Text(),
		}); err != nil {
			logrus.Fatal(err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Debugf("added %d items", resp.GetAdded())
}

func bloomInfo(cmd *cobra.Command, args []string) {
	got, err := clt.BloomInfo(context.TODO(), &emptypb.Empty{})
	if err != nil {
		logrus.Fatal(err)
	}
	fmt.Printf("Capacity: %d\n", got.GetCapacity())
	fmt.Printf("Elements: %d\n", got.GetElements())
	fmt.Printf("# Hashfuncs: %d\n", got.GetHashfuncs())
	fmt.Printf("FP Probability: %v\n", got.GetFpprob())
	fmt.Printf("Bits: %d\n", got.GetBits())
}

func bloomSave(cmd *cobra.Command, args []string) {
	_, err := clt.BloomSave(context.TODO(), &emptypb.Empty{})
	if err != nil {
		logrus.Fatal(err)
	}
}

func bloomReload(cmd *cobra.Command, args []string) {
	_, err := clt.BloomReload(context.TODO(), &emptypb.Empty{})
	if err != nil {
		logrus.Fatal(err)
	}
}

var bloomInfoCmd = &cobra.Command{
	Use:   "show",
	Short: "print information on Bloom filter",
	Long:  `The 'bloom info' command shows stats on the Bloom filter in FEVER's Bloom filter matcher.`,
	Run:   bloomInfo,
}

var bloomAddCmd = &cobra.Command{
	Use:   "add",
	Short: "add items to Bloom filter",
	Long:  `The 'bloom add' command adds IoCs from stdin into FEVER's Bloom filter matcher.`,
	Run:   bloomAdd,
}

var bloomSaveCmd = &cobra.Command{
	Use:   "save",
	Short: "save Bloom filter to disk",
	Long:  `The 'bloom save' command persists the current state of FEVER's Bloom filter matcher to disk.`,
	Run:   bloomSave,
}

var bloomReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "reload Bloom filter from disk",
	Long:  `The 'bloom reload' command reloads FEVER's Bloom filter from disk.`,
	Run:   bloomReload,
}

var bloomCmd = &cobra.Command{
	Use:   "bloom",
	Short: "bloom",
	Long:  `The 'bloom' command interacts with FEVER's Bloom filter matcher.`,
}

func init() {
	rootCmd.AddCommand(bloomCmd)
	bloomCmd.AddCommand(bloomAddCmd)
	bloomCmd.AddCommand(bloomInfoCmd)
	bloomCmd.AddCommand(bloomSaveCmd)
	bloomCmd.AddCommand(bloomReloadCmd)

	bloomCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		var err error
		mgmtCfg := mgmt.EndpointConfigFromViper()
		conn, err = grpc.Dial(mgmtCfg.DialString(), mgmtCfg.DialOptions...)
		if err != nil {
			return err
		}
		clt = mgmt.NewMgmtServiceClient(conn)
		return nil
	}

	bloomCmd.PersistentPostRunE = func(cmd *cobra.Command, args []string) error {
		return conn.Close()
	}
}
