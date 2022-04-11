#!/usr/bin/env node

const zmq = require('zeromq/v5-compat');
const cors = require('cors');
const jayson = require("jayson");
const crypto = require('crypto');
const connect = require('connect');
const bodyParser = require('body-parser');



const app = connect();

const ENCLAVE_URI = 'tcp://localhost:5552';
const _INVALID_PARAM = -32602;
var c = [];
// const socket = new zmq.Request
const socket = zmq.socket('req');
socket.sendHighWaterMark = 1000;
socket.sendTimeout = 5000;
socket.connect(ENCLAVE_URI);

socket.on('message', msg => {
    console.log('Message received');
    msg = JSON.parse(msg);
    console.log(msg);
    c[msg.id](null, msg);
})

// for await (const [msg] of socket) {
//     console.log('Received ' + ': [' + msg.toString() + ']');
//     // await sock.send('World');
//     // Do some 'work'
//     // const id = generateId()
//     // console.log(id)
// }
function generateId() {
    return crypto.randomBytes(5).toString('hex');
}


const server = new jayson.Server ({
    getEnclaveReport: async function(args, callback) {
        const id = generateId()
        c[id] = callback;
        try {
            await socket.send(JSON.stringify({id : id, type : 'GetEnclaveReport'}))
        } catch (err) {
            callback(err);
        }
    },

    newTaskEncryptionKey: async function(args, callback) {

        const id = generateId()
        c[id] = callback;
        if(args.userPubKey && args.userPubKey.length == 130) {
            try {

                await socket.send(JSON.stringify({
                    id: id,
                    type: 'NewTaskEncryptionKey',
                    userPubKey: args.userPubKey
                }));


            } catch (err) {
                callback(err);
            }


            // for await (const [msg] of socket ){
            //     console.log('Message received');
            //     console.log(JSON.parse(msg.toString()));
            //     c[JSON.parse(msg.toString()).id](null, JSON.parse(msg.toString()));
            // }


        }
        else
            {
                return callback({
                    code: _INVALID_PARAM,
                    message: "Invalid params"
                });

            }

        },
// generate totp is called when we need to verify that a user is indeed who they
//    they are but this needs your secret token
    newTotp: async function(args, callback) {

        const id = generateId()
        c[id] = callback;
        if(args.userPubKey && args.userPubKey.length == 130) {
            try {
                await socket.send(JSON.stringify({
                    id : id,
                    type : 'getTotpKey',
                    userPubKey: args.userPubKey
                }));
            } catch (err) {
                callback(err);
            }
            // for await (const [msg] of socket ){
            //     console.log('Message received');
            //     console.log(JSON.parse(msg.toString()));
            //     c[JSON.parse(msg.toString()).id](null, JSON.parse(msg.toString()));
            // }

        } else {
            return callback({
                code: _INVALID_PARAM,
                message: "Invalid params"
            });
        }

    },
    addPersonalData: async function(args, callback) {

        const id = generateId()
        c[id] = callback;
        if(args.encryptedUserId && args.userPubKey && args.encryptedData
        && args.taskSign) {
            try {
                await socket.send(JSON.stringify({
                    id : id,
                    type : 'AddPersonalData',
                    input: {
                        encryptedUserId: args.encryptedUserId,
                        encryptedData: args.encryptedData,
                        userPubKey: args.userPubKey,
                        taskSign: args.taskSign,
                        // dataTag: args.dataTag
                    }
                }));

            } catch (err) {
                callback(err);
            }
            // const [result] = await socket.receive();
            // console.log(result);
            // for await (const [msg] of socket ){
            //     console.log('Message received');
            //     console.log(JSON.parse(msg.toString()));
            //     c[JSON.parse(msg.toString()).id](null, JSON.parse(msg.toString()));
            // }

        } else {
            return callback({
                code: _INVALID_PARAM,
                message: "Invalid params"
            });
        }
    },
    findMatch: async function(args, callback) {
        const id = generateId()
        c[id] = callback;
        if(args.encryptedUserId && args.userPubKey) {
            try {
                await socket.send(JSON.stringify({
                    id : id,
                    type : 'FindMatch',
                    input: {
                        encryptedUserId: args.encryptedUserId,
                        userPubKey: args.userPubKey
                    }
                }));
            } catch (err) {
                callback(err);
            }
        } else {
            return callback({
                code: _INVALID_PARAM,
                message: "Invalid params"
            });
        }
    },





});
// async function run() {
//     console.log("Connecting to TA");
//
//
//
//     const id = generateId()
//     console.log(id)
//     console.log("Producer bound to port 5552")
//
//
//     for await (const [msg] of sock) {
//         console.log('Received ' + ': [' + msg.toString() + ']');
//         // await sock.send('World');
//         // Do some 'work'
//         // const id = generateId()
//         // console.log(id)
//     }
// }
//
// run();
// const server = jayson.server({
// })
app.use(cors({methods: ['POST']}));
app.use(bodyParser.json({ limit: "20mb" }));
app.use(bodyParser.urlencoded({ limit: "20mb", extended: true}));
app.use(server.middleware());
app.listen(8080);