const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const webauthn = require('webauthn');
const base64url = require('base64url');
//const https=require('https');
const fs=require('fs');
const path = require('path');

require('dotenv').config();


//const cert= fs.readFileSync('C:\\Users\\dubey\\OneDrive\\Desktop\\Fingerprint Authentication\\cert.pem');
//const key= fs.readFileSync('C:\\Users\\dubey\\OneDrive\\Desktop\\Fingerprint Authentication\\key.pem');

const app = express();


app.use(cors({
    origin: 'http://127.0.0.1:5500', // Allow only this origin
    methods: ['GET', 'POST', 'OPTIONS'], // Allow these methods
    credentials: true // Allow cookies and authentication headers
}));

app.use(bodyParser.json());
app.use(session({ secret:process.env.SECRET_KEY,
 resave: false, saveUninitialized: true }))



const users = {}; 
app.options('/register', (req, res) => {
    res.header('Access-Control-Allow-Origin', 'http://127.0.0.1:5500');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(204);
  });

app.post('/register', (req, res) => {
    console.log('Received POST /register request');
    console.log('Request body:', req.body);
    
    const { username } = req.body;
    if (!username) return res.status(400).send('Username is required');

        
    

    const user = users[username] || { id: base64url.encode(webauthn.generateRandomBuffer(32)), authenticators: [] };
    users[username] = user;

    const challenge = base64url.encode(webauthn.generateChallenge());
    req.session.challenge = challenge;

    const registrationOptions = {
        challenge,
        rp: {
            name: 'Your App',
            id: 'localhost'
        },
        user: {
            id: user.id,
            name: username,
            displayName: username
        },
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 }
        ]
    };

    res.json(registrationOptions);
});

app.post('/register/verify', async (req, res) => {
    console.log('POST/REGISTER CALLED');
    const { username, attestation } = req.body;
    if (!username || !attestation) return res.status(400).send('Username and attestation are required');

    const user = users[username];
    if (!user) return res.status(400).send('User not found');

    const verification = await webauthn.verifyRegistrationResponse({
        credential: attestation,
        expectedChallenge: req.session.challenge,
        expectedOrigin: 'http://127.0.0.1:5500',
        expectedRPID :'localhost'
    });

    if (verification.verified) {
        user.authenticators.push(verification.authenticatorInfo);
        res.json({ status: 'ok' });
    } else {
        res.status(400).json({ status: 'failed' });
    }
});

app.use(express.static(path.join(__dirname)));


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

//const server = https.createServer({ key, cert }, app);

app.listen(3000, () => {
    console.log('HTTPS Server running on port 3000');
});