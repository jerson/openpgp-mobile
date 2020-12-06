const myWorker = new Worker('worker.js');

const sample = async () => {

    let pbf = new Pbf();
    GenerateRequest.write({
        options: {
            name: 'sample',
            email: 'sample@sample.com'
        }
    }, pbf)
    const buf = pbf.finish()
    const rawResponse = await send(buf)

    const response = KeyPairResponse.read(new Pbf(rawResponse))
    if (response.error) {
        throw new Error(response.error)
    }
    console.log('response', response.keyPair);
}

let counter = 0;
const send = (request) => {
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
            myWorker.removeEventListener('message', callback)
            const data = e.data || {}
            if (id !== data.id) {
                reject('not same id')
                return
            }
            console.log('Worker said : ', data.response);
            resolve(data.data);
        }

        myWorker.addEventListener('message', callback)
        myWorker.addEventListener('error', callbackError)
        myWorker.addEventListener("messageerror", callbackMessageError)
        myWorker.postMessage({id, request});
    })
}