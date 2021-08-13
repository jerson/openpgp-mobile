import * as flatbuffers from 'flatbuffers';
import {Cipher, Compression, Hash, KeyOptions, Options} from "../libs/bridge";
import {GenerateRequest} from "../libs/model/generate-request";
import {KeyPairResponse} from "../libs/model/key-pair-response";

export const GenerateSample = async () => {

    const builder = new flatbuffers.Builder(0);

    KeyOptions.startKeyOptions(builder);
    KeyOptions.addCipher(builder, Cipher.AES256);
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