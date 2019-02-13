package types

// DCSO FEVER
// Copyright (c) 2017, 2018, DCSO GmbH

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// FlowEvent stores the meta-data of a flow event in a compact, binary form.
type FlowEvent struct {
	Timestamp     uint64
	Format        byte
	SrcIP         []byte
	DestIP        []byte
	SrcPort       uint16
	DestPort      uint16
	BytesToServer uint32
	BytesToClient uint32
	PktsToServer  uint32
	PktsToClient  uint32
	Flags         uint16
}

// FlowEventFlags defines various flags for use in FlowEvent.Flags (e.g. the protocol).
var FlowEventFlags = map[string]uint16{
	"TCP": 1 << 0,
	"UDP": 1 << 1,
}

var maxBytes = int64(^uint32(0))

func parseIP(stringIP string) ([]byte, error) {
	ip := net.ParseIP(stringIP)
	if ip == nil {
		return nil, errors.New("invalid IP")
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		//this is an IPv6 address
		reverseIP(ip)
		return ip, nil
	}
	//this is an IPv4 address
	reverseIP(ipv4)
	return ipv4, nil
}

func reverseIP(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
}

// FromEntry populates a FlowEvent using an Entry
func (fe *FlowEvent) FromEntry(e *Entry) error {
	ts, err := time.Parse(SuricataTimestampFormat, e.Timestamp)
	if err != nil {
		return err
	}

	srcIP, err := parseIP(e.SrcIP)
	if err != nil {
		return err
	}

	destIP, err := parseIP(e.DestIP)
	if err != nil {
		return err
	}

	flags := uint16(0)

	if e.Proto == "TCP" {
		flags |= FlowEventFlags["TCP"]
	}

	if e.Proto == "UDP" {
		flags |= FlowEventFlags["UDP"]
	}

	fe.Timestamp = uint64(ts.UnixNano())
	fe.SrcIP = srcIP
	fe.SrcPort = uint16(e.SrcPort)
	fe.DestIP = destIP
	fe.DestPort = uint16(e.DestPort)

	fe.Format = 1

	if len(srcIP) == 16 {
		fe.Format |= 1 << 1
	}

	fe.Format |= 1 << 2 //bits 3,4,5 and 6 mark the version (currently 1)

	if len(srcIP) != len(destIP) {
		return fmt.Errorf("source and destination IPS have different lengths O.o")
	}

	if e.BytesToServer > maxBytes {
		return errors.New("BytesToServer is too large")
	}

	if e.BytesToClient > maxBytes {
		return errors.New("BytesToClient is too large")
	}

	if e.PktsToServer > maxBytes {
		return errors.New("PktsToServer is too large")
	}

	if e.PktsToClient > maxBytes {
		return errors.New("PktsToClient is too large")
	}

	fe.BytesToServer = uint32(e.BytesToServer)
	fe.BytesToClient = uint32(e.BytesToClient)
	fe.PktsToServer = uint32(e.PktsToServer)
	fe.PktsToClient = uint32(e.PktsToClient)
	fe.Flags = flags

	return nil

}

// Unmarshal reads a FlowEvent from an io.Reader.
func (fe *FlowEvent) Unmarshal(reader io.Reader) error {

	bs1 := make([]byte, 1)
	bs2 := make([]byte, 2)
	bs4 := make([]byte, 4)
	bs8 := make([]byte, 8)

	//format
	if _, err := io.ReadFull(reader, bs1); err != nil {
		return err
	}
	fe.Format = bs1[0]
	if fe.Format&0x01 != 0x01 {
		return fmt.Errorf("invalid format byte (should start with a 1)")
	}

	isIPv6 := (fe.Format & 0x02) == 0x02

	//timestamp
	if _, err := io.ReadFull(reader, bs8); err != nil {
		return err
	}
	fe.Timestamp = binary.LittleEndian.Uint64(bs8)

	//src ip
	if isIPv6 {
		fe.SrcIP = make([]byte, 4*4)
		if _, err := io.ReadFull(reader, fe.SrcIP); err != nil {
			return err
		}
	} else {
		fe.SrcIP = make([]byte, 4)
		if _, err := io.ReadFull(reader, fe.SrcIP); err != nil {
			return err
		}
	}

	//src port
	if _, err := io.ReadFull(reader, bs2); err != nil {
		return err
	}
	fe.SrcPort = binary.LittleEndian.Uint16(bs2)

	//dest ip
	if isIPv6 {
		fe.DestIP = make([]byte, 4*4)
		if _, err := io.ReadFull(reader, fe.DestIP); err != nil {
			return err
		}
	} else {
		fe.DestIP = make([]byte, 4)
		if _, err := io.ReadFull(reader, fe.DestIP); err != nil {
			return err
		}
	}

	//dest port
	if _, err := io.ReadFull(reader, bs2); err != nil {
		return err
	}
	fe.DestPort = binary.LittleEndian.Uint16(bs2)

	//PktsToServer
	if _, err := io.ReadFull(reader, bs4); err != nil {
		return err
	}
	fe.PktsToServer = binary.LittleEndian.Uint32(bs4)

	//PktsToClient
	if _, err := io.ReadFull(reader, bs4); err != nil {
		return err
	}
	fe.PktsToClient = binary.LittleEndian.Uint32(bs4)

	//BytesToServer
	if _, err := io.ReadFull(reader, bs4); err != nil {
		return err
	}
	fe.BytesToServer = binary.LittleEndian.Uint32(bs4)

	//BytesToClient
	if _, err := io.ReadFull(reader, bs4); err != nil {
		return err
	}
	fe.BytesToClient = binary.LittleEndian.Uint32(bs4)

	//Flags
	if _, err := io.ReadFull(reader, bs2); err != nil {
		return err
	}
	fe.Flags = binary.LittleEndian.Uint16(bs2)

	return nil
}

// Marshal writes a FlowEvent to an io.Writer.
func (fe *FlowEvent) Marshal(writer io.Writer) error {

	bs1 := make([]byte, 1)
	bs2 := make([]byte, 2)
	bs4 := make([]byte, 4)
	bs8 := make([]byte, 8)

	//format
	bs1[0] = fe.Format
	writer.Write(bs1)

	//timestamp
	binary.LittleEndian.PutUint64(bs8, fe.Timestamp)
	writer.Write(bs8)

	//src ip
	writer.Write(fe.SrcIP)

	//src port
	binary.LittleEndian.PutUint16(bs2, fe.SrcPort)
	writer.Write(bs2)

	//dest ip
	writer.Write(fe.DestIP)

	//dest port
	binary.LittleEndian.PutUint16(bs2, fe.DestPort)
	writer.Write(bs2)

	//PktsToServer
	binary.LittleEndian.PutUint32(bs4, fe.PktsToServer)
	writer.Write(bs4)

	//PktsToClient
	binary.LittleEndian.PutUint32(bs4, fe.PktsToClient)
	writer.Write(bs4)

	//BytesToServer
	binary.LittleEndian.PutUint32(bs4, fe.BytesToServer)
	writer.Write(bs4)

	//BytesToClient
	binary.LittleEndian.PutUint32(bs4, fe.BytesToClient)
	writer.Write(bs4)

	//Flags
	binary.LittleEndian.PutUint16(bs2, fe.Flags)
	writer.Write(bs2)

	return nil

}
