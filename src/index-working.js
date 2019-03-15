const AES    = require('crypto-js/aes');
const Utf8   = require('crypto-js/enc-utf8');
const Hex = require('crypto-js/enc-hex');
const Base64 = require('crypto-js/enc-base64');
const HmacSHA256 = require('crypto-js/hmac-sha256');
const URLBase64 = require('urlsafe-base64');
const crypto = require('crypto');

const versionHex = '80';

//lpad a string for some hex conversions
function lpad(str, padString, length){
  while (str.length < length) str = padString + str;
  return str;
}

//Makes a Base64 string a url-safe base64 string
function urlsafe(string) {
  return string.replace(/\+/g, '-').replace(/\//g, '_') //.replace(/=+$/, '')
}

// parse a Hex string to an Int
const parseHex = (hexString)=> {
  return parseInt('0x' + hexString);
}

// turn bits into number of chars in a hex string
function hexBits(bits){
  return bits / 8 * 2;
}

// convert base64 string to hex string
function decode64toHex(string){
  const s = URLBase64.decode(string.replace(/=+$/, ''));
  return (new Buffer(s)).toString('hex');
}

// convert array to hex string
function ArrayToHex(array){
  let hex = '';
  for( const _byte in array){
    hex += lpad(Number(_byte).toString(16), '0',2);
  }
  return hex;
}

function randomHex(size) {
  return crypto.randomBytes(128/8).toString('hex')
}

function setIV(iv_array){
  let ivHex;
  if(iv_array){
    ivHex = ArrayToHex(iv_array);
  }else{
    ivHex = randomHex(128/8);
  }
  // this.iv = Hex.parse(this.ivHex);
  return ivHex;
}

//convert Time object or now into WordArray
function timeBytes(time){
  if(time){
    time = (time / 1000)
  }else{
    time = (Math.round(new Date() / 1000))
  }
  const hexTime = lpad(time.toString(16), '0', '16')
  return Hex.parse(hexTime);
}

function setSecret(secret64){
  return new Secret(secret64);
}

function encryptMessage(message, encryptionKey, iv){
  const encrypted = AES.encrypt(message, encryptionKey, {iv: iv});
  return encrypted.ciphertext;
}

function decryptMessage(cipherText, encryptionKey, iv){
  const encrypted = {};
  encrypted.key=encryptionKey;
  encrypted.iv=iv;
  encrypted.ciphertext = cipherText;

  const decrypted = AES.decrypt(encrypted, encryptionKey, {iv: iv});

  return decrypted.toString(Utf8);
}

function createToken(signingKey, time, iv, cipherText){
  const hmac = createHmac(signingKey, time, iv, cipherText);
  let tokenWords = Hex.parse(versionHex);
  tokenWords = tokenWords.concat(time);
  tokenWords = tokenWords.concat(iv);
  tokenWords = tokenWords.concat(cipherText);
  tokenWords = tokenWords.concat(hmac);
  console.log('CREATE TOKEN TW: ', tokenWords)
  return urlsafe(tokenWords.toString(Base64));
}

function createHmac(signingKey, time, iv, cipherText) {
  console.log('logging:WRK:DEFAULT VERSION HEX: ', versionHex)
  let hmacWords = Hex.parse(versionHex);
  console.log('logging:WRK:HMAC WORDS FROM HEX PARSE: ', hmacWords)
  console.log('logging:WRK:ARGS: ', time, iv, cipherText);
  hmacWords = hmacWords.concat(time);
  hmacWords = hmacWords.concat(iv);
  hmacWords = hmacWords.concat(cipherText);
  
  console.log('logging:WRK:CREATE HMAC hw: ', hmacWords)
  return HmacSHA256(hmacWords, signingKey);
}

export class Secret {
  constructor(secret64){
    const secret = decode64toHex(secret64);
    if (secret.length !== hexBits(256)) {
        throw new Error('Secret must be 32 url-safe base64-encoded bytes.');
    }
    this.signingKeyHex    = secret.slice(0, hexBits(128));
    this.signingKey       = Hex.parse(this.signingKeyHex);
    this.encryptionKeyHex = secret.slice( hexBits(128));
    this.encryptionKey    = Hex.parse(this.encryptionKeyHex);
  }
  
}


export class Token{
  constructor(opts={}, parent={}){
    opts = opts || {};
    this._fernet = parent;
    this.secret     = opts.secret || parent.secret;
    this.ttl        = opts.ttl    || parent.ttl;
    if(opts.ttl === 0) this.ttl = 0;
    this.message    = opts.message;
    this.cipherText = opts.cipherText;
    this.token      = opts.token;
    this.version    = opts.version || parseHex(parent.versionHex);
    this.optsIV     = opts.iv;
    this.maxClockSkew  = 60;
    if(opts.time) {
      this.setTime(Date.parse(opts.time));
      this._options = opts;
    } else {
      this.setTime();
    }
    console.log('logging:WRK: OPTS? ', opts)
    console.log('logging:time: ', this.time, timeBytes(new Date()), timeBytes())
    //this.setIV = setIV;
    this.ivHex = setIV(opts.iv);
    this.iv = Hex.parse(this.ivHex);

  }

  
  setTime(time){
    this.time = timeBytes(time);
  }

  toString(){
    if(this.encoded){
      return this.token;
    }else{
      return this.message;
    }
  }

  encode(message){
    if(!this.secret) throw(new Error("Secret not set"));
    this.encoded = true;
    setIV(this.optsIV);  //if null will always be a fresh IV
    this.message = message || this.message;
    this.cipherText = encryptMessage(this.message, this.secret.encryptionKey, this.iv);
    this.token = createToken(this.secret.signingKey,this.time, this.iv, this.cipherText)
    return this.token;
  }

  decode(token){
    if(!this.secret) throw(new Error("Secret not set"));
    this.encoded = false;
    this.token = token || this.token;

    var tokenString   = decode64toHex(this.token);
    var versionOffset = hexBits(8);
    var timeOffset    = versionOffset + hexBits(64);
    var ivOffset      = timeOffset + hexBits(128);
    var hmacOffset    = tokenString.length - hexBits(256);
    var timeInt       = parseHex(tokenString.slice(versionOffset, timeOffset));

    this.version  = parseHex(tokenString.slice(0,versionOffset));

    if(this.version != 128){
      throw new Error("Invalid version");
    }

    this.time     = new Date(timeInt * 1000);

    var currentTime = new Date()
    var timeDiff = (currentTime - this.time) / 1000;

    if(this.ttl > 0 && timeDiff > this.ttl) {
      throw new Error("Invalid Token: TTL");
    }

    if(((currentTime / 1000) + this.maxClockSkew) < timeInt){
      throw new Error("far-future timestamp");
    }

    this.ivHex    = tokenString.slice(timeOffset, ivOffset);
    this.iv       = Hex.parse(this.ivHex);
    this.cipherTextHex = tokenString.slice(ivOffset, hmacOffset);
    this.cipherText = Hex.parse(this.cipherTextHex);
    this.hmacHex    = tokenString.slice(hmacOffset);
    var decodedHmac = createHmac(this.secret.signingKey, timeBytes(this.time), this.iv, this.cipherText);
    var decodedHmacHex = decodedHmac.toString(Hex);

    var accum = 0
    for(var i=0;i<64;i++){
      accum += decodedHmacHex.charCodeAt(i) ^ this.hmacHex.charCodeAt(i)
    }
    if(accum != 0) throw new Error("Invalid Token: HMAC");

    this.message     = decryptMessage(this.cipherText, this.secret.encryptionKey, this.iv)
    return this.message;
  }
}


