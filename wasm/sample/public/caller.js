const myWorker = new Worker('worker.js');

const sample = async () => {

    let pbf = new Pbf();
    GenerateRequest.write({
        options: {
            name: 'sample',
            comment: '',
            passphrase: '',
            email: 'sample@sample.com',
            keyOptions: {
                rsaBits: 1024
            }
        }
    }, pbf)
    const buf = pbf.finish()
    console.log('request', buf);
    const rawResponse = await send('generate', buf)

    const response = KeyPairResponse.read(new Pbf(rawResponse))
    if (response.error) {
        throw new Error(response.error)
    }
    console.log('response', response.output);
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