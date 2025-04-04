// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

import { KeyOptions } from '../model/key-options.js';


export class Options {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):Options {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsOptions(bb:flatbuffers.ByteBuffer, obj?:Options):Options {
  return (obj || new Options()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsOptions(bb:flatbuffers.ByteBuffer, obj?:Options):Options {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new Options()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

name():string|null
name(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
name(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

comment():string|null
comment(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
comment(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

email():string|null
email(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
email(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

passphrase():string|null
passphrase(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
passphrase(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

keyOptions(obj?:KeyOptions):KeyOptions|null {
  const offset = this.bb!.__offset(this.bb_pos, 12);
  return offset ? (obj || new KeyOptions()).__init(this.bb!.__indirect(this.bb_pos + offset), this.bb!) : null;
}

static startOptions(builder:flatbuffers.Builder) {
  builder.startObject(5);
}

static addName(builder:flatbuffers.Builder, nameOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, nameOffset, 0);
}

static addComment(builder:flatbuffers.Builder, commentOffset:flatbuffers.Offset) {
  builder.addFieldOffset(1, commentOffset, 0);
}

static addEmail(builder:flatbuffers.Builder, emailOffset:flatbuffers.Offset) {
  builder.addFieldOffset(2, emailOffset, 0);
}

static addPassphrase(builder:flatbuffers.Builder, passphraseOffset:flatbuffers.Offset) {
  builder.addFieldOffset(3, passphraseOffset, 0);
}

static addKeyOptions(builder:flatbuffers.Builder, keyOptionsOffset:flatbuffers.Offset) {
  builder.addFieldOffset(4, keyOptionsOffset, 0);
}

static endOptions(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

}
