const express = require("express");
const rsa = require('../../rsaul/rsa-cybersecurity');

const sha = require('object-sha');

const app = express();
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');

const bigconv = require('bigint-conversion');

// settings
app.set('port', process.env.PORT || 2000);
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

global.puKey;
global.prKey;
global.Key;
global.iv;


async function claves() {
  const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

  puKey = publicKey;
  prKey = privateKey;

};



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




app.post("/mensaje3", async (req, res) => {

  clientePublicKey = new rsa.PublicKey(bigconv.hexToBigint(req.body.mensaje.e), bigconv.hexToBigint(req.body.mensaje.n));
  console.log(clientePublicKey);
 
  if ( await verifyHash(clientePublicKey) == true) {

  
    Key = req.body.mensaje.body.msg;
    
    iv= req.body.mensaje.iv;

    console.log("IV 1:" + iv);
    console.log(Key);
     
    const body = {
      type: '4',
      src: 'TTP',
      ttp: 'TTP',
      dst:['B', 'A'],
      msg : req.body.mensaje.body.msg
      
    }

    const digest = await digestHash(body);

    const pkp = bigconv.bigintToHex(prKey.sign(bigconv.textToBigint(digest)));

    res.status(200).send({
      body, pkp
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
    console.log(bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.pko))))
    var verify = false;

    if (hashBody == bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.pko)))) {
      verify = true
    }
    console.log(verify);

    return verify
  }

});

app.get('/claveparabob', (req, res) => {

  res.status(200).send({key: Key, iv: iv})
    console.log(Key);
    console.log(iv);
  });
   