import * as flatbuffers from 'flatbuffers';
import {Algorithm, Cipher, Compression, Hash, KeyOptions, Options} from "../libs/model";
import {GenerateRequest} from "../libs/model/generate-request";
import {GetPublicKeyMetadataRequest} from '../libs/model/get-public-key-metadata-request';
import {PublicKeyMetadataResponse} from '../libs/model/public-key-metadata-response';
import {KeyPairResponse} from "../libs/model/key-pair-response";
import {PrivateKeyMetadataResponse} from '../libs/model/private-key-metadata-response';
import {GetPrivateKeyMetadataRequest} from '../libs/model/get-private-key-metadata-request';
import { ArmorDecodeRequest } from '../libs/model/armor-decode-request';
import { ArmorDecodeResponse } from '../libs/model/armor-decode-response';

export const GenerateSample = async () => {
    console.log("GenerateSample")

const encoded = `-----BEGIN PGP MESSAGE-----
Version: openpgp-mobile

cmFuZG9tIHN0cmluZw==
-----END PGP MESSAGE-----`

    const builder = new flatbuffers.Builder(0);

    KeyOptions.startKeyOptions(builder);
    KeyOptions.addCipher(builder, Cipher.AES256);
    KeyOptions.addAlgorithm(builder, Algorithm.EDDSA);
    KeyOptions.addCompression(builder, Compression.ZLIB);
    KeyOptions.addCompressionLevel(builder, 9);
    KeyOptions.addHash(builder, Hash.SHA512);
    KeyOptions.addRsaBits(builder, 1024);
    const offsetKeyOptions = KeyOptions.endKeyOptions(builder)

    const name = builder.createString('sample')
    const comment = builder.createString('sample')
    const passphrase = builder.createString('sample')
    const email = builder.createString('sample@sample.com')

    Options.startOptions(builder);
    Options.addName(builder, name);
    Options.addComment(builder, comment);
    Options.addEmail(builder, email);
    Options.addPassphrase(builder, passphrase);
    Options.addKeyOptions(builder, offsetKeyOptions);
    const offsetOptions = Options.endOptions(builder)

    GenerateRequest.startGenerateRequest(builder);
    GenerateRequest.addOptions(builder, offsetOptions);
    const offset = GenerateRequest.endGenerateRequest(builder);
    builder.finish(offset);

    const bytes = builder.asUint8Array()

    console.log('request', bytes);
    const rawResponse = await sendToWorker('generate', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = KeyPairResponse.getRootAsKeyPairResponse(responseBuffer)
    if (response.error()) {
        throw new Error(response.error()!)
    }
    const output = response.output()
    console.log('privateKey', output!.privateKey());
    console.log('publicKey', output!.publicKey());

    await MetadataPublicKey(output!.publicKey()|| '')
    await MetadataPrivateKey(output!.privateKey()|| '')
    await ArmorDecode(encoded)
   
}


const ArmorDecode = async (message: string) => {

    console.log("ArmorDecode")
    const builder = new flatbuffers.Builder(0);
    const messageOffset = builder.createString(message)
    
    ArmorDecodeRequest.startArmorDecodeRequest(builder)
    ArmorDecodeRequest.addMessage(builder, messageOffset);
    const offsetMetadata = ArmorDecodeRequest.endArmorDecodeRequest(builder);
    builder.finish(offsetMetadata);
    const bytes = builder.asUint8Array()
    const rawResponse = await sendToWorker('armorDecode', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = ArmorDecodeResponse.getRootAsArmorDecodeResponse(responseBuffer)
    if (response.error()) {
        throw new Error(response.error()!)
    }
    const output = response.output()
  
    console.log('bodyArray',  output?.bodyArray());
    console.log('type', output?.type());
}

const MetadataPublicKey = async (publicKey: string) => {
    console.log("MetadataPublicKey")
    const builder = new flatbuffers.Builder(0);
    const publicKeyOffset = builder.createString(publicKey)
    
    GetPublicKeyMetadataRequest.startGetPublicKeyMetadataRequest(builder)
    GetPublicKeyMetadataRequest.addPublicKey(builder, publicKeyOffset);
    const offsetMetadata = GenerateRequest.endGenerateRequest(builder);
    builder.finish(offsetMetadata);
    const bytes = builder.asUint8Array()
    const rawResponse = await sendToWorker('getPublicKeyMetadata', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = PublicKeyMetadataResponse.getRootAsPublicKeyMetadataResponse(responseBuffer)
    if (response.error()) {
        throw new Error(response.error()!)
    }
    const output = response.output()
    const identity = output!.identities(0)!
    console.log('canEncrypt', output!.canEncrypt());
    console.log('canSign', output!.canSign());
    console.log('algorithm', output!.algorithm());
    console.log('email', identity?.email());
    console.log('name', identity?.name());
    console.log('comment', identity?.comment());
    console.log('id', identity?.id());
}

const MetadataPrivateKey = async (publicKey: string) => {
    console.log("MetadataPrivateKey")
    const builder = new flatbuffers.Builder(0);
    const publicKeyOffset = builder.createString(publicKey)
    
    GetPrivateKeyMetadataRequest.startGetPrivateKeyMetadataRequest(builder)
    GetPrivateKeyMetadataRequest.addPrivateKey(builder, publicKeyOffset);
    const offsetMetadata = GenerateRequest.endGenerateRequest(builder);
    builder.finish(offsetMetadata);
    const bytes = builder.asUint8Array()
    const rawResponse = await sendToWorker('getPrivateKeyMetadata', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = PrivateKeyMetadataResponse.getRootAsPrivateKeyMetadataResponse(responseBuffer)
    if (response.error()) {
        throw new Error(response.error()!)
    }
    const output = response.output()
    const identity = output!.identities(0)!
    console.log('canSign', output!.canSign());
    console.log('email', identity?.email());
    console.log('name', identity?.name());
    console.log('comment', identity?.comment());
    console.log('id', identity?.id());
}

let counter = 0;
const sendToWorker = (name:string, request:Uint8Array) => {
    const myWorker = new Worker('worker.js');
    counter++;
    const id = counter.toString()

    return new Promise<Uint8Array>((resolve, reject) => {

        const callbackError = (e:any) => {
            reject('callbackError: ' + e)
        }
        const callbackMessageError = (e:any) => {
            reject('callbackMessageError: ' + e)
        }
        const callback = (e:any) => {
            const data = e.data || {}
            if (id !== data.id) {
                // if not same if we should not reject
                return
            }
            myWorker.removeEventListener('message', callback)
            const {error, response} = data;
            if (error) {
                reject(error)
            }
            resolve(response);
        }

        myWorker.addEventListener('message', callback)
        myWorker.addEventListener('error', callbackError)
        myWorker.addEventListener("messageerror", callbackMessageError)
        myWorker.postMessage({id, name, request});
    })
}