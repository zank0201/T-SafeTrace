#!/usr/bin/env node
const client = require('prom-client');
const zmq = require('zeromq/v5-compat');
const cors = require('cors');
const jayson = require("jayson");
const crypto = require('crypto');
// const connect = require('connect');
const express = require('express');
// const startServer = require('./node-prometheus-grafana/node-application-monitoring-app');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const app = express();




// const collectDefaultMetrics = client.collectDefaultMetrics;
// collectDefaultMetrics();
const ENCLAVE_URI = 'tcp://10.42.0.172:5552';
const _INVALID_PARAM = -32602;
var c = [];
// const socket = new zmq.Request
// var accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' })
const socket = zmq.socket('req');
socket.sendHighWaterMark = 1000;
socket.sendTimeout = 5000;
socket.connect(ENCLAVE_URI);
// const register = new client.Registry();

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
        console.log(args);
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
        console.log(args);
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



// dash.attach();
// app.use(startServer);
app.use(cors({methods: ['POST']}));
app.use(bodyParser.json({ limit: "20mb" }));
app.use(bodyParser.urlencoded({ limit: "20mb", extended: true}));
// app.use();
app.use(server.middleware());
// startServer()
app.listen(9200, () => {
    console.log('we are listening to port 9001')
})
