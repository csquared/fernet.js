/** 
 * This an es6 port of the library found here:
 *    https://github.com/csquared/fernet.js
 * 
 * This was ported due to issues with the global module scope and caused issues with rollup.js.
 */
import AES from 'crypto-js/aes';
import Utf8 from 'crypto-js/enc-utf8';
import Hex from 'crypto-js/enc-hex';
import Base64 from 'crypto-js/enc-base64';
import HmacSHA256 from 'crypto-js/hmac-sha256';
import URLBase64 from 'urlsafe-base64';
const crypto = require('crypto');
import defaults from './defaults';

/**
 * left pad a string for some hex conversions (changed to function rather than messing with the string prototype)
 * 
 * @param {String} str - input string for padding
 * @param {String} padString - pad string to prepend input string
 * @param {Number} length - length of output padded string
 * @return {String} the padded string
 */
function lpad(str, padString, length){
  while (str.length < length) str = padString + str;
  return str;
}

/**
 * Makes a Base64 string a url-safe base64 string
 * @param {String} string - input string to make url-safe
 * @return {String} a url-safe base64 string
 */
function urlsafe(string) {
  return string.replace(/\+/g, '-').replace(/\//g, '_') //.replace(/=+$/, '')
}

/**
 * parse a Hex string to an Int
 * @param {String} hexString - a hexlified string
 * @return {Number} resulting integer from input hex string
 */
const parseHex = (hexString)=> {
  return parseInt('0x' + hexString);
}

/**
 * turn bits into number of chars in a hex string
 * @param {Number} bits - input bits to conver to thex
 * @return {Number} number of chars in hex string
 */
function hexBits(bits){
  return bits / 8 * 2;
}

/**
 * convert base64 string to hex string
 * @param {String} string - input base64 string to hex
 * @return {String} a hex string
 */
function decode64toHex(string){
  const s = URLBase64.decode(string.replace(/=+$/, ''));
  return (new Buffer.from(s)).toString('hex');
}

/**
 * convert array to hex string
 * @param {Number[]} array - iv array of integers
 * @return {String} a hex string
 */
function ArrayToHex(array){
  let hex = '';
  for( const _byte in array){
    hex += lpad(Number(_byte).toString(16), '0', 2);
  }
  return hex;
}

/**
 * Creates a random hex string
 * @param {Number} size - size of hex string
 * @return {String} a hex string
 */
function randomHex(size) {
  return crypto.randomBytes(128/8).toString('hex');
}

/**
 * Will safely create an IV Array of integers
 * @param {Number[]} [iv_array=null] - array of numbers for IV array.  If none passed in, a random hex will be created
 * @return {String} a hex string 
 */
function setIV(iv_array=null){
  return Array.isArray(iv_array) ? ArrayToHex(iv_array): randomHex(128/8);
}

/**
 * convert Time object or now into WordArray
 * @param {Date} time - input Date object to convert to WordArray
 * @return {Number[]} a word array
 */
function timeBytes(time){
  if(time){
    time = (time / 1000)
  }else{
    time = (Math.round(new Date() / 1000))
  }
  const hexTime = lpad(time.toString(16), '0', '16')
  return Hex.parse(hexTime);
}

/**
 * convenience function to create a new instance of a Secret() and sets it as the default for all future tokens
 * @param {String} secret64 - base64 encoded secret string
 * @return {Secret} a Secret
 */
function setSecret(secret64){
  defaults.secret = new Secret(secret64);
  return defaults.secret;
}

/**
 * Encrypts a message using AES 
 * @param {String} message - message to encrypt
 * @param {String} encryptionKey - encryption key for AES
 * @param {Number[]} iv - IV array
 * @return {String} encrypted message
 */
function encryptMessage(message, encryptionKey, iv){
  const encrypted = AES.encrypt(message, encryptionKey, {iv: iv});
  return encrypted.ciphertext;
}

/**
 * Decrypts an AES Encrypted message
 * @param {String} cipherText - the encrypted message
 * @param {String} encryptionKey - decryption key for AES
 * @param {Number[]} iv - IV array
 * @return {String} decrypted message
 */
function decryptMessage(cipherText, encryptionKey, iv){
  const encrypted = {
    ciphertext: cipherText,
    key: encryptionKey,
    iv: iv
  };

  const decrypted = AES.decrypt(encrypted, encryptionKey, {iv: iv});
  return decrypted.toString(Utf8);
}

/**
 * creates an encryption token
 * @param {Number[]} signingKey - signing key for encyrption
 * @param {Date} time - time stamp for verification
 * @param {Number[]} iv - IV Array
 * @param {String} cipherText - the cipher text
 * @return {String} the url safe encrypted string
 */
function createToken(signingKey, time, iv, cipherText){
  const hmac = createHmac(signingKey, time, iv, cipherText);
  let tokenWords = Hex.parse(defaults.versionHex);
  for (let c of [time, iv, cipherText, hmac]){
    tokenWords = tokenWords.concat(c);
  }
  return urlsafe(tokenWords.toString(Base64));
}

/**
 * Creates a SHA256 undigested byte string
 * @param {Number[]} signingKey - signing key for encyrption
 * @param {Date} time - time stamp for verification
 * @param {Number[]} iv - IV Array
 * @param {String} cipherText - the cipher text
 * @return {String} an undigested byte string
 */
function createHmac(signingKey, time, iv, cipherText) {
  let hmacWords = Hex.parse(defaults.versionHex);
  for (let c of [time, iv, cipherText]){
    hmacWords = hmacWords.concat(c);
  }
  return HmacSHA256(hmacWords, signingKey);
}


/**
 * Instance of a Secret to be used for the token encryption
 */
class Secret {
  /**
   * Creates a Secret to be used for the token encryption
   * @param {String} secret64 - base64 encoded secret string
   */
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

/**
 * Options for token object to perform encryption
 * @typedef TokenOptions
 * @property {Number} [ttl=60] - time to live in seconds
 * @property {Secret} secret - Secret object to use for encryption/decryption
 * @property {String} message - message to encrypt
 * @property {String} cipherText - cipher text to decrypt
 * @property {String} token - a token string
 * @property {String} [version='80'] - version of the token
 * @property {Number[]} iv - IV Array
 */

/**
 * Token object to perform encryption/decryption
 */
class Token {
  /**
   * Token object to perform encryption/decryption
   * @param {TokenOptions} opts - options for token initialization
   */
  constructor(opts={}){
    opts = opts || {};
    this.secret     = opts.secret || defaults.secret;
    this.ttl        = opts.ttl    || defaults.ttl;
    if(opts.ttl === 0) this.ttl = 0;
    this.message    = opts.message;
    this.cipherText = opts.cipherText;
    this.token      = opts.token;
    this.version    = opts.version || parseHex(defaults.versionHex);
    this.optsIV     = opts.iv;
    this.maxClockSkew  = 60;
    this.time = opts.time ? timeBytes(Date.parse(opts.time)): timeBytes();
  }

  /**
   * converts token to string
   * @return {String} to stringified token
   */
  toString(){
    return this.encoded ? this.token: this.message;
  }

  /**
   * Encrypts a message
   * @param {String} message - message to encrypt
   * @return {String} encoded token string
   */
  encode(message){
    if(!this.secret) throw(new Error("Secret not set"));
    this.encoded = true;
    this.ivHex = setIV(this.optsIV);
    this.iv = Hex.parse(this.ivHex);  //if null will always be a fresh IV
    this.message = message || this.message;
    this.cipherText = encryptMessage(this.message, this.secret.encryptionKey, this.iv);
    this.token = createToken(this.secret.signingKey,this.time, this.iv, this.cipherText)
    return this.token;
  }

  /**
   * Decrypts a token
   * @param {String} token - token to decrypt
   * @return {String} decoded message
   */
  decode(token){
    if(!this.secret) throw(new Error("Secret not set"));
    this.encoded = false;
    this.token = token || this.token;
    const tokenString   = decode64toHex(this.token);
    const versionOffset = hexBits(8);
    const timeOffset    = versionOffset + hexBits(64);
    const ivOffset      = timeOffset + hexBits(128);
    const hmacOffset    = tokenString.length - hexBits(256);
    const timeInt       = parseHex(tokenString.slice(versionOffset, timeOffset));

    this.version  = parseHex(tokenString.slice(0,versionOffset));

    if(this.version != 128){
      throw new Error("Invalid version");
    }

    this.time = new Date(timeInt * 1000);

    const currentTime = new Date()
    const timeDiff = (currentTime - this.time) / 1000;
  
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
    const decodedHmac = createHmac(this.secret.signingKey, timeBytes(this.time), this.iv, this.cipherText);
    const decodedHmacHex = decodedHmac.toString(Hex);

    let accum = 0
    for(let i=0;i<64;i++){
      accum += decodedHmacHex.charCodeAt(i) ^ this.hmacHex.charCodeAt(i)
    }
    if(accum != 0) throw new Error("Invalid Token: HMAC");

    this.message = decryptMessage(this.cipherText, this.secret.encryptionKey, this.iv)
    return this.message;
  }
}

/**
 * scoped fernet wrapper, where options can be passed in and scoped to this instance
 * @typedef {Object} FernetWrapper 
 * @property {Secret} - Secret Object instantiator
 * @property {Token} - initializes a new Token()
 */

/**
*  below `fernet` wrapper does not really make sense to use in es6, only implemented here for legacy support.
* This seems redundant as you can just `import { Token, Secret } from 'fernet'` in es6 and initialize the token with whatever options you want, or you can simply use the `defaults` for top level/global config of tokens.
*/ 


/**
 * creates an instance of a fernet wrapper, where options can be passed in and scoped to this instance.
 * @param {TokenOptions} opts - options for standalone instance of fernet wrapper
 * @return {FernetWrapper}
 */
function fernet(opts=null){
  // default to 'defaults'
  this.opts = opts || Object.assign({}, defaults);
  this.Secret = Secret;

  // do setup
  this.ivHex = setIV(this.opts.iv);
  this.iv = Hex.parse(this.ivHex);  //if null will always be a fresh IV
  this.ttl = opts.ttl || 60;
  // because (0 || x) always equals x
  if(opts.ttl === 0) this.ttl = 0;
  if (opts.secret){
    this.secret = new Secret(opts.secret);
  }
  const scopeThis = this;
  this.Token = ()=>{
    return new Token(scopeThis);
  }

  this.setSecret = (secret64)=> {
    this.secret = new Secret(secret64);
    return this.secret;
  }

  // legacy support
  this.encryptMessage = encryptMessage;
  this.decryptMessage = decryptMessage;
  this.createToken = createToken;
  this.createHmac = createHmac;
}

export { defaults, Secret, Token, fernet, setSecret, ArrayToHex, timeBytes, decode64toHex, createHmac, hexBits, urlsafe };


