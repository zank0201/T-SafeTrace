
const {totp } = require('otplib/index.js');
// const notp = require('notp');
const readline = require("readline")
const axios = require('axios');

const jaysonBrowserClient = require('jayson/lib/client/browser');
const JSON_RPC_Server = 'http://127.0.0.1:9200';
const StatsD = require('node-statsd'),
    client_stats = new StatsD();
const forge = require('node-forge');
const buffer = require('buffer');
const fs = require("fs");
const EC = require('elliptic').ec;
const instance = axios.create();

const callServer = function(request, callback) {
    // console.log(JSON.parse(request))
    let config = {
        headers: {
            'Content-Type': 'application/json',
            'credentials': 'include',
        },
    };
    // Request interceptor for capturing start time

    instance.interceptors.request.use((config) => {
        config.metadata = { startTime: new Date()}
        // return config;
        // config.headers['request-startTime'] = new Date().getTime();


        return config
    })

// Response interceptor for computing duration
    instance.interceptors.response.use((response) => {response.config.metadata.endTime = new Date()
        response.duration = response.config.metadata.endTime - response.config.metadata.startTime
        return response
    })

    instance.post(JSON_RPC_Server, JSON.parse(request), config).then((response) => {
        if ('error' in response.data) {
            callback(response.data.error, null);
        } else {
            let text = JSON.stringify(response.data.result);

            // console.log(request);
            // console.log(response.duration);
            // let request_json =JSON.parse(request)
            // console.log(request_json.method)
            // console.log(response.headers['request-duration'])
            // httpRequestDurationMicroseconds
            //     .labels(req.route.path)
            //     .observe(responseTimeInMs)

            if (response.data.result.type == "AddPersonalData" ) {
                instance.get('http://localhost:8080/api').then((response) =>{
                    console.log("done")
                    }
                ).catch(function(err) {
                    callback({code: -32000, message: err.message}, null);
                });

            //     let bytes = response.data.result.addPersonalData.bytesize;
            //     console.log(response.config.headers['request-startTime'])
                let join_text =response.config.metadata.startTime + "," + response.duration + "\n";
                // let file = fs.createWriteStream('log.txt', {
                //     flags: 'a' // 'a' means appending (old data will be preserved)
                // })
                // file.write(join_text);

            }
            callback(null, text);


        }
    }).catch(function(err) {
        callback({code: -32000, message: err.message}, null);
    });



};



// axios.get(JSON_RPC_Server+'/metrics', (req, res) => {
//     res.set('Content-Type', Prometheus.register.contentType)
//     res.end(Prometheus.register.metrics())
// })

const client = new jaysonBrowserClient(callServer, {});
// generate otp
//TODO add verify window
/**
 * generates otp when called
 * @param secret
 * @returns {String} 8 digit totp
 */

//TODO implement ecdh
function deriveKeys(taskpubkey,privatekey ) {
    // console.log("entered derive keys function");
    let ec = new EC("p256");
    if (taskpubkey.length == 128) {
        taskpubkey = '04' + taskpubkey;
    }
    let clientkey = ec.keyFromPrivate(privatekey, 'hex');
    let enclavekey = ec.keyFromPublic(taskpubkey, 'hex');
    let sharedPoints = enclavekey.getPublic().mul(clientkey.getPrivate());
    // let derivedkey = sharedPoints.getX();
    // let y = 0x02 | (sharedPoints.getY().isOdd()? 1 : 0)
    let x = sharedPoints.getX();
    // let buffer_y = Buffer.from([y]);
    let buffer_x = x.toArrayLike(Buffer, 'be', 32);
    let sha256 = forge.md.sha256.create();
    sha256.update(buffer_x.toString('binary'));

    return x.toString('hex');

}
/**
 * Encrypts a message using the generated task key
 * returns encrypted message in aes gcm format
 * @param {String} taskpubkey = enclave generate public key
 * @param {String} data
 * @returns {String} encrypted data
 */
function encrypt(derivedkey, data) {

    let key = forge.util.hexToBytes(derivedkey);
    let iv = forge.random.getBytesSync(12);
    let cipher = forge.cipher.createCipher('AES-GCM', key);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();
    //encrypted data result
    // console.log("print tag");
    // console.log("tag length: " + (cipher.mode.tag.toHex().length));
    // console.log("print result " + cipher.output.toHex().length);
    let result = cipher.output.putBuffer(cipher.mode.tag).putBytes(iv);
// outputs encrypted hex
//     console.log("result len" + result.toHex().length);
    return result.toHex();

}

/**
 *
 * @param taskpubkey
 * @param enc_data
 * @returns {*}
 */

function decrypt(derivedkey, enc_data) {

    let key = forge.util.hexToBytes(derivedkey);
    let msgBuf = Buffer.from(enc_data,"hex");

    let iv = forge.util.createBuffer(msgBuf.slice(-12));
    let tag = forge.util.createBuffer(msgBuf.slice(-28, -12));
    let decipher = forge.cipher.createDecipher('AES-GCM', key);
    decipher.start({iv: iv,
    tag: tag
    });
    decipher.update(forge.util.createBuffer(msgBuf.slice(0, -28)));
    if (decipher.finish()) {
        return decipher.output.toHex();
    }

    throw new Error('decipher did not finish');
}

/**
 *
 * @returns {{client_pub: *, private_buffer: *}}
 */
function ClientKeys() {
    let ec = new EC("p256");
    let keypair = ec.genKeyPair();
    let publickeys = keypair.getPublic();
    let private_key = keypair.getPrivate();
    const client_pub = publickeys.encode('hex');
    const private_buffer = private_key.toString('hex');

    return {private_buffer, client_pub}

}


/** generate unique user id for user
 *
 * @returns {string}
 */
function uniqueId() {
    return '_' + Math.random().toString(36).substr(2, 9);
}
function GenerateOtp(secret, enclavetotp) {


    totp.options = { digits: 6,
        algorithm: "sha1", encoding: 'hex', window: 10}

    let token = totp.generate(secret);
    // console.log("generated token ", token);
    let isvalid = totp.check(enclavetotp, secret);
    // let opt = {window: 200, counter: 50};
    // let token = notp.totp.gen(secret,{} );

    // console.log(isvalid);


// valid token

    return isvalid;

}

async function getTotpKey(client_pub, secret) {
    const getTotpResult = await new Promise((resolve, reject) => {
        let dataResult = false;
        client.request('newTotp', {userPubKey: client_pub},
            (err, response) => {
                if (err) {
                    reject(err);
                    return;
                }

                resolve(response);
            });

    });

    const {result, id} = getTotpResult;
    const {token} = result;
    let totpCheck = GenerateOtp(secret, token);
    return totpCheck;

}
const awaitTimeout = delay =>
    new Promise(resolve => setTimeout(resolve, delay));

async function getEncryptionKey(client_pub) {


        const getEncryptionKeyResult = await new Promise((resolve, reject) => {
            client.request('newTaskEncryptionKey', {userPubKey: client_pub},
                (err, response) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve(response);
                });
        });

        const {result, id} = getEncryptionKeyResult;
        const {taskPubKey, sig} = result;
        return {taskPubKey, sig};

        // ToDo: verify signature




}
// function parsed_data(encrypted_userid, encrypted_data, encrypted_pub) {
//     let apiData = {encrypted_test: []};
//
//
//
//     let obj_data = {"Id": encrypted_userid, "data": {"encrypt_data": encrypted_data, "key": encrypted_pub }};
//
//         // apiData.location_data.push({"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool});
//     apiData.encrpyted_test.push(obj_data);
//         // apiData.users.push({"userId": user});
//     count++;
//
//
//
//
//
//     fs.writeFileSync("data.json", JSON.stringify(apiData, null, 4));
//     return apiData;
// }


// create function to encrypt data

// function to call encryption functions from ta
// and use signature and otp to verify validity
/**
 * adds encrypted userid and location data to TA
 *
 * @param userId
 * @param data
 * @returns {Promise<void>}
 */
async function addData(gps_location) {



    let data_array = gps_location.location_data;
    for (items of data_array) {
        let {private_buffer, client_pub} = ClientKeys();
// // get result values from encryption to use signature value for verify
        try {
            // console.log("hey try");
            // console.log(response_ax);
            let {taskPubKey, sig} = await getEncryptionKey(client_pub);

            let derivedKey = deriveKeys(taskPubKey, private_buffer);

            let totp = await getTotpKey(client_pub, derivedKey);


            // for (items of data_array) {
            // let chunks = [];
            // console.log(items.userId);
            let encryptedUserId = encrypt(derivedKey, JSON.stringify(items.userId));
            // console.log(items.userId);
            // chunks.push(items.data);
            // console.log(JSON.stringify(items.data));
            // console.log("user data", JSON.stringify(items.data));
            let encryptedData = encrypt(derivedKey, JSON.stringify(items.data));
            // console.log(encryptedData);


            // client_stats.timing('response_time', 42);
            await awaitTimeout(4000);
            const addPersonalDataResult = await new Promise((resolve, reject) => {


                // if (totp == true)
                // let api_totp = GenerateOtp(derivedKey, totp_user.toString());
                // if (api_totp==false) throw "invalid totp";

                // file.write(new Date().getTime())
                // console.log(new Date().getTime())
                client.request('addPersonalData', {
                        encryptedUserId: encryptedUserId,
                        encryptedData: encryptedData,
                        userPubKey: client_pub,
                        taskSign: sig
                    },
                    (err, response) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        resolve(response);
                        // console.log(response);
                    })


            });

            // getTotpKey(client_pub).then(totp => GenerateOtp(derivedKey, totp));

            // console.log(count);
            const {addPersonalData} = addPersonalDataResult;

            if (addPersonalData.status == 0) {
                console.log('Personal data added successfully to the enclave.');
            } else {
                console.log('Something went wrong. Time to debug...')
            }
            // }
        } catch (err) {
            console.log(err);
            // Or throw an error
        }
    }
        }

// async function addData(userId, data) {
//
//
//     // let count =0;
//     // let data_array = gps_location.location_data;
//
//         let {private_buffer, client_pub} = ClientKeys();
// // // get result values from encryption to use signature value for verify
//         try {
//             // console.log("hey try");
//             let {taskPubKey, sig} = await getEncryptionKey(client_pub);
//
//             // count+=1
//             let derivedKey = deriveKeys(taskPubKey, private_buffer);
//
//             let totp = await getTotpKey(client_pub, derivedKey);
//
//
//             // for (items of data_array) {
//             // let chunks = [];
//             // console.log(items.userId);
//             let encryptedUserId = encrypt(derivedKey,userId);
//             // console.log(items.userId);
//             // chunks.push(items.data);
//             // console.log(JSON.stringify(items.data));
//             // console.log("user data", JSON.stringify(items.data));
//             let encryptedData = encrypt(derivedKey, data);
//             // console.log(encryptedData);
//
//
//             client_stats.timing('response_time', 42);
//             await awaitTimeout(3000);
//             const addPersonalDataResult = await new Promise((resolve, reject) => {
//
//
//                 // if (totp == true)
//                 // let api_totp = GenerateOtp(derivedKey, totp_user.toString());
//                 // if (api_totp==false) throw "invalid totp";
//                 client.request('addPersonalData', {
//                         encryptedUserId: encryptedUserId,
//                         encryptedData: encryptedData,
//                         userPubKey: client_pub,
//                         taskSign: sig
//                     },
//                     (err, response) => {
//                         if (err) {
//                             reject(err);
//                             return;
//                         }
//                         resolve(response);
//                         // console.log(response);
//                     })
//
//
//             });
//
//             // getTotpKey(client_pub).then(totp => GenerateOtp(derivedKey, totp));
//
//             // console.log(count);
//             const {addPersonalData} = addPersonalDataResult;
//
//             if (addPersonalData.status == 0) {
//                 console.log('Personal data added successfully to the enclave.');
//             } else {
//                 console.log('Something went wrong. Time to debug...')
//             }
//             // }
//         } catch (err) {
//             console.log(err);
//             // Or throw an error
//         }
//     // }
// }
async function findMatch(userId){

    let {private_buffer, client_pub} = ClientKeys();

    try {
        let {taskPubKey, sig} = await getEncryptionKey(client_pub);
        let derivedKey = deriveKeys(taskPubKey, private_buffer);
        let encryptedUserId = encrypt(derivedKey, userId);

        const findMatchResult = await new Promise((resolve, reject) => {
            client.request('findMatch', {
                    encryptedUserId: encryptedUserId,
                    userPubKey: client_pub},
                (err, response) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve(response);
                });
        });

        if(findMatchResult.findMatch.status == 0) {
            console.log('Find Match operation successful');

            let output = decrypt(derivedKey, findMatchResult.findMatch.encryptedOutput);

            if(output.length){
                console.log('Find matches:');
                console.log(output);
            } else {
                console.log('No matches');
            }
        } else {
            console.log('Something went wrong. Time to debug...')
        }
    } catch(err) {
        console.log(err);
        // Or throw an error
    }
}

//

//
// console.log("hey girl");
async function TestData(gps_location) {
    let apiData = {encrypted_test: []};

    let data_array = gps_location.location_data;


    // apiData.location_data.push({"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool});
    // apiData.encrpyted_test.push(obj_data);
    // apiData.users.push({"userId": user});


    for (items of data_array) {
        let {private_buffer, client_pub} = ClientKeys();
// // get result values from encryption to use signature value for verify
        try {
            // console.log("hey try");
            await awaitTimeout(4000);
            let {taskPubKey, sig} = await getEncryptionKey(client_pub);

            let derivedKey = deriveKeys(taskPubKey, private_buffer);

            // let totp = await getTotpKey(client_pub, derivedKey);




            // for (items of data_array) {
            // let chunks = [];
            // console.log(items.userId);
            let encryptedUserId = encrypt(derivedKey, JSON.stringify(items.userId));

            // chunks.push(items.data);
            let encryptedData = encrypt(derivedKey, JSON.stringify(items.data));

            let obj_data = {"Id": encryptedUserId, "encrypt_data": encryptedData, "key": client_pub, "sign": sig };

            apiData.encrypted_test.push(obj_data);
            // console.log(apiData.encrypted_test);
            fs.writeFileSync("test.json", JSON.stringify(apiData, null, 4));

            // }
        } catch(err) {
            console.log(err);
            // Or throw an error
        }
        // fs.writeFileSync("test.json", JSON.stringify(apiData, null, 4));
    }
    // fs.writeFileSync("test.json", JSON.stringify(apiData, null, 4));
    // console.log(apiData.encrypted_test);

    // fs.writeFileSync("test.json", JSON.stringify(apiData, null, 4));
}


let data1 = [
    {
        "lat": 40.757339,
        "lng": -73.985992,
        "startTS": 1583064001,
        "endTS": 1583067601,
        "testResult": false,
    },
    {
        "lat": 40.793840,
        "lng": -73.956900,
        "startTS": 1583150401,
        "endTS": 1583154001,
        "testResult": false,
    },
]
let data2 = [
    {
        "lat": 41.757339,
        "lng": -73.985992,
        "startTS": 1583064000,
        "endTS": 1583067600,
        "testResult": true,
    },
    {
        "lat": 40.793840,
        "lng": -73.956900,
        "startTS": 1583150400,
        "endTS": 1583154000,
        "testResult": true,
    },
]
// let arguments = process.argv


// addData(String(arguments[2]), JSON.stringify(arguments[3])).then();

// addData("User1", JSON.stringify(data1));
// addData("User2", JSON.stringify(data2)).then(value => {console.log(value)});

let data = fs.readFileSync('data.json');
let gps_location = JSON.parse(data);

addData(gps_location).then(console.log);
// findMatch("User1").then(console.log);
//
//
// loop_data()