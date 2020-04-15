import { Component } from '@angular/core';
import { compileNgModuleFromRender2 } from '@angular/compiler/src/render3/r3_module_compiler';
import * as sha from 'object-sha';
import * as rsa from '../../../../../rsaul/rsa-cybersecurity';
import * as big from 'bigint-crypto-utils';
import * as bigconv from 'bigint-conversion';
import {MensajeService} from '../app/service';
import { dashCaseToCamelCase } from '@angular/compiler/src/util';
import * as paillier from 'paillier-bigint';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'Alice'
  k : any;
  key :any;
  encrypt :any;
  publicKey: rsa.PublicKey;
  privateKey: rsa.PrivateKey;
  serverPublicKey: rsa.PublicKey;
  ttpPublicKey:  rsa.PublicKey;
  Keyexport: any;
  iv : any;
  
  serverPublicKeyPai: paillier.PublicKey;
  publicKeyPai: paillier.PublicKey;
  privateKeyPai: paillier.PrivateKey;

  n1: string;
  n2: string;
  suma: string;




  async ngOnInit(){

    this.dameClave();

   await this.claves();
   
   this.dameClaveTTP();
   
   this.dameclavesPai();
   this.dameClavePai();


  }


  constructor(private mensajeService: MensajeService) {

  }

  sumar(numero1, numero2){


    console.log(numero1,numero2)

    var n1 : any = bigconv.textToBigint(numero1)
    var n2 : any = bigconv.textToBigint(numero2)

    console.log(n1,n2)

    var cn1 = this.serverPublicKeyPai.encrypt(n1);
    var cn2 = this.serverPublicKeyPai.encrypt(n2);

    this.n1 = bigconv.bigintToHex(cn1);
    this.n2 = bigconv.bigintToHex(cn2);


    console.log(n1,n2)

    var body = {
      c1: this.n1,
      c2: this.n2      
    }

    this.mensajeService.send(body).subscribe((res:any) =>{
      this.suma = bigconv.bigintToText(bigconv.hexToBigint(res.suma));
      console.log(bigconv.bigintToText(bigconv.hexToBigint(res.suma)))
    })



  }

  dameClave() {
    this.mensajeService.dameClave().subscribe((res: any) => {
      this.serverPublicKey = new rsa.PublicKey(bigconv.hexToBigint(res.e), bigconv.hexToBigint(res.n))
    })
  }
  async claves() {
    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);
    this.publicKey = publicKey;
    this.privateKey = privateKey;

    
  }

  dameClavePai(){

    this.mensajeService.dameclavesPai().subscribe((res:any) => {
      this.serverPublicKeyPai = new paillier.PublicKey(bigconv.hexToBigint(res.n),bigconv.hexToBigint(res.g));
    });

  }



async dameclavesPai() {
  const { publicKey, privateKey } = await paillier.generateRandomKeysSync(3072);
  this.publicKeyPai = publicKey;
  this.privateKeyPai = privateKey;
}

  dameClaveTTP(){

    this.mensajeService.dameClaveTTP().subscribe((res: any) => {
      this.ttpPublicKey = new rsa.PublicKey(bigconv.hexToBigint(res.e), bigconv.hexToBigint(res.n))
    })



  }



  async enviarMensaje(mensaje: any)
  {
    
    var k;
    var encrypt;
    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    this.iv = iv;
    var des;
  
    var midate = new Date();
   var res : any;
    console.log(mensaje);
    var messageBuffer = this.str2ab(mensaje);


      await crypto.subtle.generateKey({
      name: "AES-CBC",
      length: 256, //can be  128, 192, or 256
  },
  true, //whether the key is extractable (i.e. can be used in exportKey)
  ["encrypt", "decrypt"] //can "encrypt", "decrypt" or  "wrapKey", or "unwrapKey"
).then(function(key) {
  console.log(key);
  k = key;
});

console.log(k);
this.key = k;

const exportKeyData = await crypto.subtle.exportKey("jwk", k)

this.Keyexport =  exportKeyData;



await crypto.subtle.encrypt(
  {
      name: "AES-CBC",
      //Don't re-use initialization vectors!
      //Always generate a new iv every time your encrypt!
      iv,
  },
  this.key, //from generateKey or importKey above
  messageBuffer //ArrayBuffer of data you want to encrypt
)
.then(function(encrypted){
  //returns an ArrayBuffer containing the encrypted data
  console.log(new Uint8Array(encrypted));
  encrypt = new Uint8Array(encrypted);

});
var body = { src: 'A', dest: 'B', msg: encrypt, type : 1, timestamp: midate}


const hash = await  this.hashbody(body);
  
const po = bigconv.bigintToHex(this.privateKey.sign(bigconv.textToBigint(hash)));
    const e = bigconv.bigintToHex(this.publicKey.e);
    const n = bigconv.bigintToHex(this.publicKey.n);

    console.log(this.publicKey)

    this.mensajeService.enviarMensaje1({body, po, e, n})

.subscribe(async (res: any) => {
  const hashBody = await sha.digest(res.body, 'SHA-256');

  if (hashBody == bigconv.bigintToText(this.serverPublicKey.verify(bigconv.hexToBigint(res.pr)))) {
    console.log(res.body)
    await this.mensnajeTPP();
  } else {
    console.log("No se ha podido verificar al servidor B")

  }
});


var as = this.ab2str(des);
console.log(as);
  }


  async mensnajeTPP(){

    var midate = new Date();
    var body = { src: 'A', TTTP: 'TTP', dest: 'B', msg: this.Keyexport, type : 1, timestamp: midate}


    
    const hash = await  this.hashbody(body);
    const pko = bigconv.bigintToHex(this.privateKey.sign(bigconv.textToBigint(hash)));
    const e = bigconv.bigintToHex(this.publicKey.e);
    const n = bigconv.bigintToHex(this.publicKey.n);
    const iv =  bigconv.bigintToHex(this.iv);
    console.log(this.publicKey)

    this.mensajeService.enviarMensaje3({body, pko, e, n})

    
.subscribe(async (res: any) => {
  const hashBody = await sha.digest(res.body, 'SHA-256');
 
  if (hashBody == bigconv.bigintToText(this.ttpPublicKey.verify(bigconv.hexToBigint(res.pkp)))) {
    console.log(res.body)
    this.avisobob();
    
  
  } else {
    console.log("Fatal veri TTP")

  }
});

  }
  




   str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

   ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
  
  }


avisobob(){

  this.mensajeService.avisobob()
  .subscribe(async (res: any) => {

    console.log('mensaje enviado a bob');


    });



}

async hashbody(body){

  const hash  = await sha.digest(body, 'SHA-256'); 
  return hash;
}


  
  }

 
  
