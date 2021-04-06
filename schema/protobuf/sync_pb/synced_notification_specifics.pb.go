// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Sync protocol datatype extension for synced notifications.
// DO NOT USE: This datatype is deprecated.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.7
// source: synced_notification_specifics.proto

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

// This message is kept around for backwards compatibility sake.
type SyncedNotificationSpecifics struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SyncedNotificationSpecifics) Reset() {
	*x = SyncedNotificationSpecifics{}
	if protoimpl.UnsafeEnabled {
		mi := &file_synced_notification_specifics_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncedNotificationSpecifics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncedNotificationSpecifics) ProtoMessage() {}

func (x *SyncedNotificationSpecifics) ProtoReflect() protoreflect.Message {
	mi := &file_synced_notification_specifics_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncedNotificationSpecifics.ProtoReflect.Descriptor instead.
func (*SyncedNotificationSpecifics) Descriptor() ([]byte, []int) {
	return file_synced_notification_specifics_proto_rawDescGZIP(), []int{0}
}

var File_synced_notification_specifics_proto protoreflect.FileDescriptor

var file_synced_notification_specifics_proto_rawDesc = []byte{
	0x0a, 0x23, 0x73, 0x79, 0x6e, 0x63, 0x65, 0x64, 0x5f, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x70, 0x62, 0x22, 0x1d,
	0x0a, 0x1b, 0x53, 0x79, 0x6e, 0x63, 0x65, 0x64, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x53, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x73, 0x42, 0x37, 0x0a,
	0x25, 0x6f, 0x72, 0x67, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e, 0x63, 0x6f,
	0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x73, 0x79, 0x6e, 0x63, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x48, 0x03, 0x50, 0x01, 0x5a, 0x0a, 0x2e, 0x2e, 0x2f, 0x73,
	0x79, 0x6e, 0x63, 0x5f, 0x70, 0x62,
}

var (
	file_synced_notification_specifics_proto_rawDescOnce sync.Once
	file_synced_notification_specifics_proto_rawDescData = file_synced_notification_specifics_proto_rawDesc
)

func file_synced_notification_specifics_proto_rawDescGZIP() []byte {
	file_synced_notification_specifics_proto_rawDescOnce.Do(func() {
		file_synced_notification_specifics_proto_rawDescData = protoimpl.X.CompressGZIP(file_synced_notification_specifics_proto_rawDescData)
	})
	return file_synced_notification_specifics_proto_rawDescData
}

var file_synced_notification_specifics_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_synced_notification_specifics_proto_goTypes = []interface{}{
	(*SyncedNotificationSpecifics)(nil), // 0: sync_pb.SyncedNotificationSpecifics
}
var file_synced_notification_specifics_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_synced_notification_specifics_proto_init() }
func file_synced_notification_specifics_proto_init() {
	if File_synced_notification_specifics_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_synced_notification_specifics_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncedNotificationSpecifics); i {
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
			RawDescriptor: file_synced_notification_specifics_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_synced_notification_specifics_proto_goTypes,
		DependencyIndexes: file_synced_notification_specifics_proto_depIdxs,
		MessageInfos:      file_synced_notification_specifics_proto_msgTypes,
	}.Build()
	File_synced_notification_specifics_proto = out.File
	file_synced_notification_specifics_proto_rawDesc = nil
	file_synced_notification_specifics_proto_goTypes = nil
	file_synced_notification_specifics_proto_depIdxs = nil
}
