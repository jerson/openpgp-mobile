const myWorker = new Worker('worker.js');


const sample = async () => {
    const response = await send({name: 'sample', email: 'sample@sample.com', comment: ''})
    console.log('response', response);
}
let counter = 0;
const send = (payload) => {
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
            console.log('Worker said : ', data.data);
            resolve(data.data);
        }

        myWorker.addEventListener('message', callback)
        myWorker.addEventListener('error', callbackError)
        myWorker.addEventListener("messageerror", callbackMessageError)
        myWorker.postMessage({id, payload});
    })
}