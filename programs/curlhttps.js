const https = require('https')

const options = {
    hostname: 'www.baidu.com',
    port: 443,
    path: '/',
    method: 'GET'
}

const doHttpRequest = () => {
    return new Promise(resolve => {
        const req = https.request(options, res => {

            res.on('data', d => {
                resolve(null)
            })
        })

        req.on('error', error => {
            console.error(error)
            resolve(null)
        })

        req.end()
    })
}


const wait = (milli) => {
    return new Promise(resolve => {
        setTimeout(resolve, milli)
    })
}


const getFirstUserData = async () => {
    while (true) {
        await doHttpRequest('https://www.baidu.com')
        // const data = await response.text()
        // console.log(data)
        await wait(1000);

    }
}

getFirstUserData()