
const {totp } = require('otplib/index.js');
// const notp = require('notp');
const readline = require("readline")
const axios = require('axios');
const jaysonBrowserClient = require('jayson/lib/client/browser');
const JSON_RPC_Server = 'http://127.0.0.1:8080';
const QRCode = require('qrcode');
const forge = require('node-forge');
const buffer = require('buffer');
const EC = require('elliptic').ec;

const callServer = function(request, callback) {
    let config = {
        headers: {
            'Content-Type': 'application/json',
            'credentials': 'include',
        },
    };
    axios.post(JSON_RPC_Server, JSON.parse(request), config).then((response) => {
        if ('error' in response.data) {
            callback(response.data.error, null);
        } else {
            let text = JSON.stringify(response.data.result);
            callback(null, text);
        }
    }).catch(function(err) {
        callback({code: -32000, message: err.message}, null);
    });
};

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
    console.log("entered derive keys function");
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
    let private = keypair.getPrivate();
    const client_pub = publickeys.encode('hex');
    const private_buffer = private.toString('hex');

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
    console.log("generated token ", token);
    let isvalid = totp.check(enclavetotp, secret);
    // let opt = {window: 200, counter: 50};
    // let token = notp.totp.gen(secret,{} );

    console.log(isvalid);


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
async function addData(userId, data) {
    let {private_buffer, client_pub} = ClientKeys();
// // get result values from encryption to use signature value for verify
    try {
        let {taskPubKey, sig} = await getEncryptionKey(client_pub);
        let derivedKey = deriveKeys(taskPubKey, private_buffer);

        let totp = await getTotpKey(client_pub, derivedKey);




        let encryptedUserId = encrypt(derivedKey, userId);
        let encryptedData = encrypt(derivedKey, data);





        const addPersonalDataResult = await new Promise((resolve, reject) => {

            if(totp==true){
            // let api_totp = GenerateOtp(derivedKey, totp_user.toString());
            // if (api_totp==false) throw "invalid totp";
            client.request('addPersonalData', {
            encryptedUserId: encryptedUserId,
            encryptedData: encryptedData,
            userPubKey: client_pub,
              taskSign: sig},
              (err, response) => {
                if (err) {
                  reject(err);
                  return;
                }
                resolve(response);
              })}

          });

            // getTotpKey(client_pub).then(totp => GenerateOtp(derivedKey, totp));

          const {addPersonalData} = addPersonalDataResult;

          if(addPersonalData.status == 0) {
            console.log('Personal data added successfully to the enclave.');
          } else {
            console.log('Something went wrong. Time to debug...')
          }
        } catch(err) {
        console.log(err);
        // Or throw an error
        }
        }

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

// addData("user1", JSON.stringify(data1)).then(console.log);
// addData("user2", JSON.stringify(data2)).then(console.log);
findMatch("user1").then(console.log);


