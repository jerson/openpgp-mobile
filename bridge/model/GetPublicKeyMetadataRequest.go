// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type GetPublicKeyMetadataRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsGetPublicKeyMetadataRequest(buf []byte, offset flatbuffers.UOffsetT) *GetPublicKeyMetadataRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &GetPublicKeyMetadataRequest{}
	x.Init(buf, n+offset)
	return x
}

func FinishGetPublicKeyMetadataRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsGetPublicKeyMetadataRequest(buf []byte, offset flatbuffers.UOffsetT) *GetPublicKeyMetadataRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &GetPublicKeyMetadataRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedGetPublicKeyMetadataRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *GetPublicKeyMetadataRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *GetPublicKeyMetadataRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *GetPublicKeyMetadataRequest) PublicKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func GetPublicKeyMetadataRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(1)
}
func GetPublicKeyMetadataRequestAddPublicKey(builder *flatbuffers.Builder, publicKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(publicKey), 0)
}
func GetPublicKeyMetadataRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
