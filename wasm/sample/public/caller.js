const myWorker = new Worker('worker.js');
const sample = async () => {

    const builder = new flatbuffers.Builder(0);
    model.Options.startOptions(builder);
    model.Options.addName(builder, builder.createString('sample'));
    model.Options.addComment(builder, builder.createString('sample'));
    model.Options.addEmail(builder, builder.createString('sample@sample.com'));
    model.Options.addPassphrase(builder, builder.createString('sample'));
    const offsetOptions = model.Options.endOptions(builder)

    model.GenerateRequest.startGenerateRequest(builder);
    model.GenerateRequest.addOptions(builder, offsetOptions);
    const offset = model.GenerateRequest.endGenerateRequest(builder);
    builder.finish(offset);

    const bytes = builder.asUint8Array()
    let hexString = "> ";
    for(let i = 0; i < bytes.length; i++){
        hexString += bytes[i].toString(16);
    }
    console.log(hexString);

    console.log('request', bytes);
    const rawResponse = await send('generate', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = model.getRootAsKeyPairResponse(responseBuffer, null)
    if (response.error()) {
        throw new Error(response.error())
    }
    console.log('response', response.output());
}

let counter = 0;
const send = (name, request) => {
    counter++;
    const id = counter.toString()

    return new Promise((resolve, reject) => {

        const callbackError = (e) => {
            reject('callbackError: ' + e)
        }
        const callbackMessageError = (e) => {
            reject('callbackMessageError: ' + e)
        }
        const callback = (e) => {
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