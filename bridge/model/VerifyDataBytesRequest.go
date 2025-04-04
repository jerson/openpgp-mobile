// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type VerifyDataBytesRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsVerifyDataBytesRequest(buf []byte, offset flatbuffers.UOffsetT) *VerifyDataBytesRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &VerifyDataBytesRequest{}
	x.Init(buf, n+offset)
	return x
}

func FinishVerifyDataBytesRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsVerifyDataBytesRequest(buf []byte, offset flatbuffers.UOffsetT) *VerifyDataBytesRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &VerifyDataBytesRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedVerifyDataBytesRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *VerifyDataBytesRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *VerifyDataBytesRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *VerifyDataBytesRequest) Signature(j int) byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		a := rcv._tab.Vector(o)
		return rcv._tab.GetByte(a + flatbuffers.UOffsetT(j*1))
	}
	return 0
}

func (rcv *VerifyDataBytesRequest) SignatureLength() int {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.VectorLen(o)
	}
	return 0
}

func (rcv *VerifyDataBytesRequest) SignatureBytes() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *VerifyDataBytesRequest) MutateSignature(j int, n byte) bool {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		a := rcv._tab.Vector(o)
		return rcv._tab.MutateByte(a+flatbuffers.UOffsetT(j*1), n)
	}
	return false
}

func (rcv *VerifyDataBytesRequest) PublicKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func VerifyDataBytesRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(2)
}
func VerifyDataBytesRequestAddSignature(builder *flatbuffers.Builder, signature flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(signature), 0)
}
func VerifyDataBytesRequestStartSignatureVector(builder *flatbuffers.Builder, numElems int) flatbuffers.UOffsetT {
	return builder.StartVector(1, numElems, 1)
}
func VerifyDataBytesRequestAddPublicKey(builder *flatbuffers.Builder, publicKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(1, flatbuffers.UOffsetT(publicKey), 0)
}
func VerifyDataBytesRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
