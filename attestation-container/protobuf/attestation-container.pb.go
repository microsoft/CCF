// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.6.1
// source: protobuf/attestation-container.proto

package protobuf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type FetchAttestationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ReportData []byte `protobuf:"bytes,1,opt,name=report_data,json=reportData,proto3" json:"report_data,omitempty"`
}

func (x *FetchAttestationRequest) Reset() {
	*x = FetchAttestationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protobuf_attestation_container_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FetchAttestationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FetchAttestationRequest) ProtoMessage() {}

func (x *FetchAttestationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protobuf_attestation_container_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FetchAttestationRequest.ProtoReflect.Descriptor instead.
func (*FetchAttestationRequest) Descriptor() ([]byte, []int) {
	return file_protobuf_attestation_container_proto_rawDescGZIP(), []int{0}
}

func (x *FetchAttestationRequest) GetReportData() []byte {
	if x != nil {
		return x.ReportData
	}
	return nil
}

type FetchAttestationReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Attestation                        []byte `protobuf:"bytes,1,opt,name=attestation,proto3" json:"attestation,omitempty"`
	AttestationEndorsementCertificates []byte `protobuf:"bytes,2,opt,name=attestation_endorsement_certificates,json=attestationEndorsementCertificates,proto3" json:"attestation_endorsement_certificates,omitempty"`
	UvmEndorsement                     []byte `protobuf:"bytes,3,opt,name=uvm_endorsement,json=uvmEndorsement,proto3" json:"uvm_endorsement,omitempty"`
}

func (x *FetchAttestationReply) Reset() {
	*x = FetchAttestationReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protobuf_attestation_container_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FetchAttestationReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FetchAttestationReply) ProtoMessage() {}

func (x *FetchAttestationReply) ProtoReflect() protoreflect.Message {
	mi := &file_protobuf_attestation_container_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FetchAttestationReply.ProtoReflect.Descriptor instead.
func (*FetchAttestationReply) Descriptor() ([]byte, []int) {
	return file_protobuf_attestation_container_proto_rawDescGZIP(), []int{1}
}

func (x *FetchAttestationReply) GetAttestation() []byte {
	if x != nil {
		return x.Attestation
	}
	return nil
}

func (x *FetchAttestationReply) GetAttestationEndorsementCertificates() []byte {
	if x != nil {
		return x.AttestationEndorsementCertificates
	}
	return nil
}

func (x *FetchAttestationReply) GetUvmEndorsement() []byte {
	if x != nil {
		return x.UvmEndorsement
	}
	return nil
}

var File_protobuf_attestation_container_proto protoreflect.FileDescriptor

var file_protobuf_attestation_container_proto_rawDesc = []byte{
	0x0a, 0x24, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x22, 0x3a, 0x0a,
	0x17, 0x46, 0x65, 0x74, 0x63, 0x68, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x72,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x22, 0xb4, 0x01, 0x0a, 0x15, 0x46, 0x65,
	0x74, 0x63, 0x68, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x70, 0x6c, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x50, 0x0a, 0x24, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x22, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x12, 0x27, 0x0a, 0x0f, 0x75, 0x76, 0x6d, 0x5f, 0x65,
	0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0e, 0x75, 0x76, 0x6d, 0x45, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x32, 0x8a, 0x01, 0x0a, 0x14, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x72, 0x0a, 0x10, 0x46, 0x65, 0x74,
	0x63, 0x68, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2e, 0x2e,
	0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x2e, 0x46, 0x65, 0x74, 0x63, 0x68, 0x41, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e,
	0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x2e, 0x46, 0x65, 0x74, 0x63, 0x68, 0x41, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x2a, 0x5a,
	0x28, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_protobuf_attestation_container_proto_rawDescOnce sync.Once
	file_protobuf_attestation_container_proto_rawDescData = file_protobuf_attestation_container_proto_rawDesc
)

func file_protobuf_attestation_container_proto_rawDescGZIP() []byte {
	file_protobuf_attestation_container_proto_rawDescOnce.Do(func() {
		file_protobuf_attestation_container_proto_rawDescData = protoimpl.X.CompressGZIP(file_protobuf_attestation_container_proto_rawDescData)
	})
	return file_protobuf_attestation_container_proto_rawDescData
}

var file_protobuf_attestation_container_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_protobuf_attestation_container_proto_goTypes = []interface{}{
	(*FetchAttestationRequest)(nil), // 0: attestation_container.FetchAttestationRequest
	(*FetchAttestationReply)(nil),   // 1: attestation_container.FetchAttestationReply
}
var file_protobuf_attestation_container_proto_depIdxs = []int32{
	0, // 0: attestation_container.AttestationContainer.FetchAttestation:input_type -> attestation_container.FetchAttestationRequest
	1, // 1: attestation_container.AttestationContainer.FetchAttestation:output_type -> attestation_container.FetchAttestationReply
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protobuf_attestation_container_proto_init() }
func file_protobuf_attestation_container_proto_init() {
	if File_protobuf_attestation_container_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protobuf_attestation_container_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FetchAttestationRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protobuf_attestation_container_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FetchAttestationReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protobuf_attestation_container_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_protobuf_attestation_container_proto_goTypes,
		DependencyIndexes: file_protobuf_attestation_container_proto_depIdxs,
		MessageInfos:      file_protobuf_attestation_container_proto_msgTypes,
	}.Build()
	File_protobuf_attestation_container_proto = out.File
	file_protobuf_attestation_container_proto_rawDesc = nil
	file_protobuf_attestation_container_proto_goTypes = nil
	file_protobuf_attestation_container_proto_depIdxs = nil
}
