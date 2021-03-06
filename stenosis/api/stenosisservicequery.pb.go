// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/stenosisservicequery.proto

package api

import (
	context "context"
	fmt "fmt"
	task "github.com/DCSO/fever/stenosis/task"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// AliveRequest contains the id to be echoed by a successful Alive() call.
type AliveRequest struct {
	// Id is the id to be echoed.
	Id                   string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AliveRequest) Reset()         { *m = AliveRequest{} }
func (m *AliveRequest) String() string { return proto.CompactTextString(m) }
func (*AliveRequest) ProtoMessage()    {}
func (*AliveRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b7526d43675a233f, []int{0}
}

func (m *AliveRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AliveRequest.Unmarshal(m, b)
}
func (m *AliveRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AliveRequest.Marshal(b, m, deterministic)
}
func (m *AliveRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AliveRequest.Merge(m, src)
}
func (m *AliveRequest) XXX_Size() int {
	return xxx_messageInfo_AliveRequest.Size(m)
}
func (m *AliveRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AliveRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AliveRequest proto.InternalMessageInfo

func (m *AliveRequest) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

// AliveResponse contains the echoed id of a preceeding Alive() request.
type AliveResponse struct {
	// Id is the echoed id of the preceeding request.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Ok is the fixed string http.StatusText(http.StatusOK)
	Ok                   string   `protobuf:"bytes,2,opt,name=ok,proto3" json:"ok,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AliveResponse) Reset()         { *m = AliveResponse{} }
func (m *AliveResponse) String() string { return proto.CompactTextString(m) }
func (*AliveResponse) ProtoMessage()    {}
func (*AliveResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b7526d43675a233f, []int{1}
}

func (m *AliveResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AliveResponse.Unmarshal(m, b)
}
func (m *AliveResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AliveResponse.Marshal(b, m, deterministic)
}
func (m *AliveResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AliveResponse.Merge(m, src)
}
func (m *AliveResponse) XXX_Size() int {
	return xxx_messageInfo_AliveResponse.Size(m)
}
func (m *AliveResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AliveResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AliveResponse proto.InternalMessageInfo

func (m *AliveResponse) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *AliveResponse) GetOk() string {
	if m != nil {
		return m.Ok
	}
	return ""
}

// QueryResponse contains the response to a QueryRequest.
type QueryResponse struct {
	// Token is the task identifying token in hex encoding.
	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	// Hateoas provides RESTful state optionally fowarded by "gRPC gateway".
	// XLinks to avoid mingling with the automatic name assignment while
	// maintaining REST API stability towards DCSO's portal.
	// This field is subject to the request's omit_additional_data flag.
	XLinks               []*HateoasLink `protobuf:"bytes,2,rep,name=_links,json=Links,proto3" json:"_links,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *QueryResponse) Reset()         { *m = QueryResponse{} }
func (m *QueryResponse) String() string { return proto.CompactTextString(m) }
func (*QueryResponse) ProtoMessage()    {}
func (*QueryResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b7526d43675a233f, []int{2}
}

func (m *QueryResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_QueryResponse.Unmarshal(m, b)
}
func (m *QueryResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_QueryResponse.Marshal(b, m, deterministic)
}
func (m *QueryResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryResponse.Merge(m, src)
}
func (m *QueryResponse) XXX_Size() int {
	return xxx_messageInfo_QueryResponse.Size(m)
}
func (m *QueryResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryResponse proto.InternalMessageInfo

func (m *QueryResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *QueryResponse) GetXLinks() []*HateoasLink {
	if m != nil {
		return m.XLinks
	}
	return nil
}

func init() {
	proto.RegisterType((*AliveRequest)(nil), "api.AliveRequest")
	proto.RegisterType((*AliveResponse)(nil), "api.AliveResponse")
	proto.RegisterType((*QueryResponse)(nil), "api.QueryResponse")
}

func init() { proto.RegisterFile("api/stenosisservicequery.proto", fileDescriptor_b7526d43675a233f) }

var fileDescriptor_b7526d43675a233f = []byte{
	// 268 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x90, 0xcf, 0x6a, 0xf3, 0x30,
	0x10, 0xc4, 0x89, 0x83, 0x03, 0x9f, 0xf2, 0xa5, 0x24, 0x22, 0x07, 0xe3, 0x43, 0x08, 0xa6, 0x50,
	0x9f, 0x24, 0x48, 0x9f, 0xa0, 0x7f, 0x0e, 0x3d, 0x94, 0x96, 0xda, 0xb7, 0x5e, 0x8a, 0x92, 0x6c,
	0x9b, 0x45, 0xa9, 0xa5, 0x7a, 0x15, 0x43, 0xdf, 0xbe, 0xc8, 0x12, 0xc1, 0xed, 0x45, 0x30, 0xab,
	0xfd, 0x49, 0x33, 0xc3, 0x56, 0xca, 0xa2, 0x24, 0x07, 0x8d, 0x21, 0x24, 0x82, 0xb6, 0xc3, 0x1d,
	0x7c, 0x9d, 0xa0, 0xfd, 0x16, 0xb6, 0x35, 0xce, 0xf0, 0xb1, 0xb2, 0x98, 0xcf, 0x9d, 0x22, 0x2d,
	0x07, 0xe3, 0x7c, 0xe1, 0xb1, 0x83, 0x72, 0x60, 0x14, 0x85, 0x51, 0xb1, 0x62, 0xff, 0x6f, 0x8e,
	0xd8, 0x41, 0xe5, 0x79, 0x72, 0xfc, 0x82, 0x25, 0xb8, 0xcf, 0x46, 0xeb, 0x51, 0xf9, 0xaf, 0x4a,
	0x70, 0x5f, 0x48, 0x36, 0x8b, 0xf7, 0x64, 0x4d, 0x43, 0xf0, 0x77, 0xc1, 0x6b, 0xa3, 0xb3, 0x24,
	0x68, 0xa3, 0x8b, 0x27, 0x36, 0x7b, 0xf1, 0x5f, 0x9e, 0x81, 0x25, 0x4b, 0x9d, 0xd1, 0xd0, 0x44,
	0x26, 0x08, 0x7e, 0xc5, 0x26, 0x6f, 0x47, 0x6c, 0x34, 0x65, 0xc9, 0x7a, 0x5c, 0x4e, 0x37, 0x73,
	0xa1, 0x2c, 0x8a, 0x87, 0xe0, 0xed, 0x11, 0x1b, 0x5d, 0xa5, 0xfe, 0xa4, 0x8d, 0x65, 0xcb, 0x3a,
	0x06, 0xad, 0x43, 0xd0, 0xfe, 0x79, 0x2e, 0x58, 0xda, 0x1b, 0xe3, 0x8b, 0x9e, 0x1c, 0x86, 0xc8,
	0xf9, 0x70, 0x14, 0x6d, 0x94, 0x2c, 0x0d, 0xe0, 0x54, 0xf8, 0x5e, 0x44, 0x2f, 0xe2, 0xe6, 0x2f,
	0xc3, 0xb7, 0x97, 0xaf, 0xc5, 0x07, 0xba, 0xc3, 0x69, 0x2b, 0x76, 0xe6, 0x53, 0xde, 0xdf, 0xd5,
	0xcf, 0xf2, 0x1d, 0x3a, 0x68, 0xcf, 0x85, 0x4b, 0x65, 0x71, 0x3b, 0xe9, 0xfb, 0xbb, 0xfe, 0x09,
	0x00, 0x00, 0xff, 0xff, 0x10, 0xd1, 0x5a, 0xf6, 0x8b, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// StenosisServiceQueryClient is the client API for StenosisServiceQuery service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type StenosisServiceQueryClient interface {
	// Alive checks whether a gRPC server is actively listening to requests by
	// echoing the request id.
	Alive(ctx context.Context, in *AliveRequest, opts ...grpc.CallOption) (*AliveResponse, error)
	// Query forwards a task.Query and responds with an identifying task.Token in
	// return.
	Query(ctx context.Context, in *task.Query, opts ...grpc.CallOption) (*QueryResponse, error)
}

type stenosisServiceQueryClient struct {
	cc *grpc.ClientConn
}

func NewStenosisServiceQueryClient(cc *grpc.ClientConn) StenosisServiceQueryClient {
	return &stenosisServiceQueryClient{cc}
}

func (c *stenosisServiceQueryClient) Alive(ctx context.Context, in *AliveRequest, opts ...grpc.CallOption) (*AliveResponse, error) {
	out := new(AliveResponse)
	err := c.cc.Invoke(ctx, "/api.StenosisServiceQuery/Alive", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *stenosisServiceQueryClient) Query(ctx context.Context, in *task.Query, opts ...grpc.CallOption) (*QueryResponse, error) {
	out := new(QueryResponse)
	err := c.cc.Invoke(ctx, "/api.StenosisServiceQuery/Query", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// StenosisServiceQueryServer is the server API for StenosisServiceQuery service.
type StenosisServiceQueryServer interface {
	// Alive checks whether a gRPC server is actively listening to requests by
	// echoing the request id.
	Alive(context.Context, *AliveRequest) (*AliveResponse, error)
	// Query forwards a task.Query and responds with an identifying task.Token in
	// return.
	Query(context.Context, *task.Query) (*QueryResponse, error)
}

// UnimplementedStenosisServiceQueryServer can be embedded to have forward compatible implementations.
type UnimplementedStenosisServiceQueryServer struct {
}

func (*UnimplementedStenosisServiceQueryServer) Alive(ctx context.Context, req *AliveRequest) (*AliveResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Alive not implemented")
}
func (*UnimplementedStenosisServiceQueryServer) Query(ctx context.Context, req *task.Query) (*QueryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Query not implemented")
}

func RegisterStenosisServiceQueryServer(s *grpc.Server, srv StenosisServiceQueryServer) {
	s.RegisterService(&_StenosisServiceQuery_serviceDesc, srv)
}

func _StenosisServiceQuery_Alive_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AliveRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StenosisServiceQueryServer).Alive(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.StenosisServiceQuery/Alive",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StenosisServiceQueryServer).Alive(ctx, req.(*AliveRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StenosisServiceQuery_Query_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(task.Query)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StenosisServiceQueryServer).Query(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.StenosisServiceQuery/Query",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StenosisServiceQueryServer).Query(ctx, req.(*task.Query))
	}
	return interceptor(ctx, in, info, handler)
}

var _StenosisServiceQuery_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.StenosisServiceQuery",
	HandlerType: (*StenosisServiceQueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Alive",
			Handler:    _StenosisServiceQuery_Alive_Handler,
		},
		{
			MethodName: "Query",
			Handler:    _StenosisServiceQuery_Query_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/stenosisservicequery.proto",
}
