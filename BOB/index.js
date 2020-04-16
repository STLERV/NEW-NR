const express = require("express");
const rsa = require('../../rsaul/rsa-cybersecurity');
const sha = require('object-sha');
const request = require('request');
const paillierBigint = require('paillier-bigint');

const app = express();
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const sss = require('shamirs-secret-sharing')

const bigconv = require('bigint-conversion');

// settings
app.set('port', process.env.PORT || 3000);
app.set('json spaces', 2);

app.listen(app.get('port'), () => {
  claves();
    console.log(`Server on port ${app.get('port')}`);
  });
  
// middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());


const ___dirname = path.resolve();

global.puKey;
global.prKey;
global.Key;
global.puKeyPai;
global.prKeyPai;


//shami

global.SKey = null;
global.c;
global.sharesServer;

async function claves() {
  const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);
  const paillierKeyPair = await paillierBigint.generateRandomKeysSync(3072);
  puKey = publicKey;
  prKey = privateKey;
  puKeyPai = paillierKeyPair.publicKey;
  prKeyPai = paillierKeyPair.privateKey;


};



app.get("/shamir", (req, res) => {

  const secret = Buffer.from('La vacuna para el COVID-19 es simplemente azucar')
  const shares = sss.split(secret, { shares: 3, threshold: 2 })
  sharesServer = shares;
  console.log(sharesServer)
  const cosas = {
    respuestaServidor: shares
  }
  res.status(200).send(cosas);
});

app.post("/getShamirKey", (req, res) => {
  console.log(req.body[0])
  if (req.body.length == 1) {
    const secret = sss.combine([sharesServer[Number(req.body[0])]]);

    const cosas = {
      respuestaServidor: secret
    }
    res.status(200).send(cosas);

  } else if (req.body.length == 2) {
    const secret = sss.combine([sharesServer[Number(req.body[0])], sharesServer[Number(req.body[1])]]);

    const cosas = {
      respuestaServidor: secret
    }
    res.status(200).send(cosas);

  } else if (req.body.length == 3) {
    const secret = sss.combine([sharesServer[Number(req.body[0])], sharesServer[Number(req.body[1])], sharesServer[Number(req.body[2])]]);

    const cosas = {
      respuestaServidor: secret
    }
    res.status(200).send(cosas);

  } else {
    res.status(400).send("ERRROR");
  }

});





app.get('/keypai', (req, res) => {

  class PublicKey {
    constructor(n, g) {
      this.n = bigconv.bigintToHex(n);
      this.g = bigconv.bigintToHex(g);
    }
  }

  publicKey = new PublicKey(
    puKeyPai.n,
    puKeyPai.g
  )

  res.status(200).send(publicKey);

});

app.post("/suma", (req, res) => {

 
  sumaCifrada = bigconv.bigintToHex(prKeyPai.decrypt(puKeyPai.addition(bigconv.hexToBigint(req.body.c1),bigconv.hexToBigint(req.body.c2))));

  const cosas = {
    suma: sumaCifrada
  }
  res.status(200).send(cosas);
});

app.get('/key', (req, res) => {

  class PublicKey {
    constructor(e, n) {
      this.e = bigconv.bigintToHex(e);
      this.n = bigconv.bigintToHex(n);
    }
  }

  publicKey = new PublicKey(
    puKey.e,
    puKey.n
  )

  res.status(200).send(publicKey);

});


app.post("/mensaje1", async (req, res) => {

  clientePublicKey = new rsa.PublicKey(bigconv.hexToBigint(req.body.mensaje.e), bigconv.hexToBigint(req.body.mensaje.n));
  console.log(clientePublicKey);
 
  if ( await verifyHash(clientePublicKey) == true) {

   
    Key = req.body.mensaje.body.msg;
    console.log(Key);
     
    const body = {
      type: '2',
      src: 'B',
      dst: 'A',
      
    }

    const digest = await digestHash(body);

    const pr = bigconv.bigintToHex(prKey.sign(bigconv.textToBigint(digest)));

    res.status(200).send({
      body, pr
    });

  } else {
    res.status(400).send("No se ha podido verificar al cliente A");
  }

  async function digestHash(body){
    const d = await sha.digest(body, 'SHA-256');
    return d;
  }

  async function verifyHash(clientePublicKey) {
    const hashBody = await sha.digest(req.body.mensaje.body, 'SHA-256')

    console.log(hashBody);
    console.log(bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.po))))
    var verify = false;

    if (hashBody == bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.po)))) {
      verify = true
    }
    console.log(verify);

    return verify
  }

});


app.get('/avisobob', (req, res) => {

  res.status(200).send({mensaje: 'correct' });
 getTTPClave(); 
});


function getTTPClave(){

request('http://localhost:2000/claveparabob', { json: true }, (err, res, body) => {
    if (err) { return console.log(err); }

    console.log(body.key);
    console.log('iv', body.iv);
 
    
  });


}

     
 
