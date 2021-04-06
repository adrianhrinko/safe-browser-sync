// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Sync protocol datatype extension for the favicon tracking type.

// If you change or add any fields in this file, update proto_visitors.h and
// potentially proto_enum_conversions.{h, cc}.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.7
// source: favicon_tracking_specifics.proto

package sync_pb

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

// Tracking info for of favicon images. These control expiration of images
// from sync based on recency, bookmark state, etc.
type FaviconTrackingSpecifics struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The url of the favicon image.
	FaviconUrl *string `protobuf:"bytes,1,opt,name=favicon_url,json=faviconUrl" json:"favicon_url,omitempty"`
	// The last time a page using this favicon was visited (in milliseconds
	// since linux epoch).
	LastVisitTimeMs *int64 `protobuf:"varint,3,opt,name=last_visit_time_ms,json=lastVisitTimeMs" json:"last_visit_time_ms,omitempty"`
	// Whether this favicon is currently bookmarked or not.
	IsBookmarked *bool `protobuf:"varint,4,opt,name=is_bookmarked,json=isBookmarked" json:"is_bookmarked,omitempty"`
}

func (x *FaviconTrackingSpecifics) Reset() {
	*x = FaviconTrackingSpecifics{}
	if protoimpl.UnsafeEnabled {
		mi := &file_favicon_tracking_specifics_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FaviconTrackingSpecifics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FaviconTrackingSpecifics) ProtoMessage() {}

func (x *FaviconTrackingSpecifics) ProtoReflect() protoreflect.Message {
	mi := &file_favicon_tracking_specifics_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FaviconTrackingSpecifics.ProtoReflect.Descriptor instead.
func (*FaviconTrackingSpecifics) Descriptor() ([]byte, []int) {
	return file_favicon_tracking_specifics_proto_rawDescGZIP(), []int{0}
}

func (x *FaviconTrackingSpecifics) GetFaviconUrl() string {
	if x != nil && x.FaviconUrl != nil {
		return *x.FaviconUrl
	}
	return ""
}

func (x *FaviconTrackingSpecifics) GetLastVisitTimeMs() int64 {
	if x != nil && x.LastVisitTimeMs != nil {
		return *x.LastVisitTimeMs
	}
	return 0
}

func (x *FaviconTrackingSpecifics) GetIsBookmarked() bool {
	if x != nil && x.IsBookmarked != nil {
		return *x.IsBookmarked
	}
	return false
}

var File_favicon_tracking_specifics_proto protoreflect.FileDescriptor

var file_favicon_tracking_specifics_proto_rawDesc = []byte{
	0x0a, 0x20, 0x66, 0x61, 0x76, 0x69, 0x63, 0x6f, 0x6e, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x6b, 0x69,
	0x6e, 0x67, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x07, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x70, 0x62, 0x22, 0x8d, 0x01, 0x0a, 0x18,
	0x46, 0x61, 0x76, 0x69, 0x63, 0x6f, 0x6e, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x53,
	0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x66, 0x61, 0x76, 0x69,
	0x63, 0x6f, 0x6e, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x66,
	0x61, 0x76, 0x69, 0x63, 0x6f, 0x6e, 0x55, 0x72, 0x6c, 0x12, 0x2b, 0x0a, 0x12, 0x6c, 0x61, 0x73,
	0x74, 0x5f, 0x76, 0x69, 0x73, 0x69, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x6d, 0x73, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0f, 0x6c, 0x61, 0x73, 0x74, 0x56, 0x69, 0x73, 0x69, 0x74,
	0x54, 0x69, 0x6d, 0x65, 0x4d, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x69, 0x73, 0x5f, 0x62, 0x6f, 0x6f,
	0x6b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x69,
	0x73, 0x42, 0x6f, 0x6f, 0x6b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x64, 0x42, 0x37, 0x0a, 0x25, 0x6f,
	0x72, 0x67, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x70,
	0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x73, 0x79, 0x6e, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x48, 0x03, 0x50, 0x01, 0x5a, 0x0a, 0x2e, 0x2e, 0x2f, 0x73, 0x79, 0x6e,
	0x63, 0x5f, 0x70, 0x62,
}

var (
	file_favicon_tracking_specifics_proto_rawDescOnce sync.Once
	file_favicon_tracking_specifics_proto_rawDescData = file_favicon_tracking_specifics_proto_rawDesc
)

func file_favicon_tracking_specifics_proto_rawDescGZIP() []byte {
	file_favicon_tracking_specifics_proto_rawDescOnce.Do(func() {
		file_favicon_tracking_specifics_proto_rawDescData = protoimpl.X.CompressGZIP(file_favicon_tracking_specifics_proto_rawDescData)
	})
	return file_favicon_tracking_specifics_proto_rawDescData
}

var file_favicon_tracking_specifics_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_favicon_tracking_specifics_proto_goTypes = []interface{}{
	(*FaviconTrackingSpecifics)(nil), // 0: sync_pb.FaviconTrackingSpecifics
}
var file_favicon_tracking_specifics_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_favicon_tracking_specifics_proto_init() }
func file_favicon_tracking_specifics_proto_init() {
	if File_favicon_tracking_specifics_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_favicon_tracking_specifics_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FaviconTrackingSpecifics); i {
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
			RawDescriptor: file_favicon_tracking_specifics_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_favicon_tracking_specifics_proto_goTypes,
		DependencyIndexes: file_favicon_tracking_specifics_proto_depIdxs,
		MessageInfos:      file_favicon_tracking_specifics_proto_msgTypes,
	}.Build()
	File_favicon_tracking_specifics_proto = out.File
	file_favicon_tracking_specifics_proto_rawDesc = nil
	file_favicon_tracking_specifics_proto_goTypes = nil
	file_favicon_tracking_specifics_proto_depIdxs = nil
}
