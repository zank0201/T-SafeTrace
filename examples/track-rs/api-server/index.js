#!/usr/bin/env node

const zmq = require('zeromq');
const cors = require('cors');
const jayson = require("jayson");
const crypto = require('crypto');
const connect = require('connect');
const bodyParser = require('body-parser');


const app = connect();

const ENCLAVE_URI = 'tcp://localhost:5552';
const _INVALID_PARAM = -32602;
var c = [];


function generateId() {
    return crypto.randomBytes(5).toString('hex');
}
async function run() {
    console.log("Connecting to TA");

    const sock = new zmq.Request
    sock.connect(ENCLAVE_URI)

    const id = generateId()
    console.log(id)
    console.log("Producer bound to port 5552")


    for await (const [msg] of sock) {
        console.log('Received ' + ': [' + msg.toString() + ']');
        // await sock.send('World');
        // Do some 'work'
        // const id = generateId()
        // console.log(id)
    }
}

run();
// const server = jayson.server({
// })
// app.use(cors({methods: ['POST']}));
// app.use(bodyParser.json({ limit: "20mb" }));
// app.use(bodyParser.urlencoded({ limit: "20mb", extended: true}));
// app.use(server.middleware());
// app.listen(8080);