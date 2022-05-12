// automatically generated by the FlatBuffers compiler, do not modify

import * as flatbuffers from 'flatbuffers';

export class ArmorDecodeRequest {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
__init(i:number, bb:flatbuffers.ByteBuffer):ArmorDecodeRequest {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsArmorDecodeRequest(bb:flatbuffers.ByteBuffer, obj?:ArmorDecodeRequest):ArmorDecodeRequest {
  return (obj || new ArmorDecodeRequest()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsArmorDecodeRequest(bb:flatbuffers.ByteBuffer, obj?:ArmorDecodeRequest):ArmorDecodeRequest {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new ArmorDecodeRequest()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

packet():string|null
packet(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
packet(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

static startArmorDecodeRequest(builder:flatbuffers.Builder) {
  builder.startObject(1);
}

static addPacket(builder:flatbuffers.Builder, packetOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, packetOffset, 0);
}

static endArmorDecodeRequest(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createArmorDecodeRequest(builder:flatbuffers.Builder, packetOffset:flatbuffers.Offset):flatbuffers.Offset {
  ArmorDecodeRequest.startArmorDecodeRequest(builder);
  ArmorDecodeRequest.addPacket(builder, packetOffset);
  return ArmorDecodeRequest.endArmorDecodeRequest(builder);
}
}