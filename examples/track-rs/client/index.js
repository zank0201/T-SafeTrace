const { authenticator, totp } = require('otplib');
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

const client = jaysonBrowserClient(callServer, {});
// generate otp
//TODO add verify window
/**
 * generates otp when called
 * @param secret
 * @returns {String} 8 digit totp
 */
function GenerateOtp(secret) {
    totp.options = { digits: 8 };
    const token = totp.generate(secret);
    return token;
}
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
    let y = 0x02 | (sharedPoints.getY().isOdd()? 1 : 0)
    let x = sharedPoints.getX();
    let buffer_y = Buffer.from([y]);
    let buffer_x = x.toArrayLike(Buffer, 'be', 32);
    let sha256 = forge.md.sha256.create();
    sha256.update(buffer_y.toString('binary'));
    sha256.update(buffer_x.toString('binary'));
    return sha256.digest().toHex();

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
    let result = cipher.output.putBuffer(cipher.mode.tag).putBytes(iv);
// outputs encrypted hex
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
        return taskPubKey;

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
async function addData(userId) {
    let {private_buffer, client_pub} = ClientKeys();
// // get result values from encryption to use signature value for verify
    try {
        let taskPubKey = await getEncryptionKey(client_pub);
        let derivedKey = deriveKeys(taskPubKey, private_buffer);
        let encryptedUserId = encrypt(derivedKey, userId);
        console.log(encryptedUserId);
        // let encryptedData = encrypt(derivedkey, data);

        const addPersonalDataResult = await new Promise((resolve, reject) => {
          client.request('addPersonalData', {
            encryptedUserId: encryptedUserId,
            // encryptedData: encryptedData,
            userPubKey: client_pub},
              (err, response) => {
                if (err) {
                  reject(err);
                  return;
                }
                resolve(response);
              });
          });

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

//

//
// console.log("hey girl");
let userid = uniqueId();
console.log(userid);
addData(userid);