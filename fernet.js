var CryptoJS = require('crypto-js/core');
var AES    = require('crypto-js/aes');
var Utf8   = require('crypto-js/enc-utf8');
var Latin1 = require('crypto-js/enc-latin1');
var Hex = require('crypto-js/enc-hex');
var Base64 = require('crypto-js/enc-base64');
var HmacSHA256 = require('crypto-js/hmac-sha256');
var URLBase64 = require('urlsafe-base64');

var fernet = function fernet(opts){

  String.prototype.lpad = function(padString, length) {
    var str = this;
    while (str.length < length) str = padString + str;
    return str;
  }

  this.Hex = Hex;

  //Makes a Base64 string a url-safe base64 string
  var urlsafe = function urlsafe(string){
    return string.replace(/\+/g, '-').replace(/\//g, '_') //.replace(/=+$/, '')
  }

  var parseHex = function parseHex(hexString){
    return parseInt('0x' + hexString);
  }

  var hexBits = function hexBits(bits){
    return bits / 8 * 2;
  }

  //Sets the secret from base64 encoded value
  this.setSecret = function setSecret(secret64){
    this.secret = new this.Secret(secret64);
    return this.secret;
  }

  var decode64toHex = function decode64(string){
    var s = URLBase64.decode(string.replace(/=+$/, ''));
    return (new Buffer(s)).toString('hex');
  }

  this.Secret = function(secret64){
    var secret = decode64toHex(secret64);
    this.signingKeyHex = secret.slice(0,hexBits(128));
    this.signingKey = Hex.parse(this.signingKeyHex);
    this.encryptionKeyHex = secret.slice(hexBits(128));
    this.encryptionKey = Hex.parse(this.encryptionKeyHex);
  }

  this.setIV = function setIV(iv_array){
    var ivHex = '';
    if(iv_array){
      for( var _byte in iv_array){
        ivHex += Number(_byte).toString(16).lpad('0',2);
      }
      this.iv = Hex.parse(ivHex);
    }else{
      this.iv = CryptoJS.lib.WordArray.random(128/8);
      ivHex = this.iv.toString(Hex);
    }
    return ivHex;
  }

  opts = opts || {};
  this.ttl = opts.ttl || 60;
  this.versionHex = '80';
  this.setIV(opts.iv);

  if(opts.secret){ this.setSecret(opts.secret) }

  this.encryptMessage = function(message, encryptionKey, iv){
    var encrypted = AES.encrypt(message, encryptionKey, {iv: iv});
    return encrypted.ciphertext;
  }

  this.decryptMessage = function(cipherText, encryptionKey, iv){
    var encrypted = {};
    encrypted.key=encryptionKey;
    encrypted.iv=iv;
    encrypted.ciphertext = cipherText;

    var decrypted = AES.decrypt(encrypted, encryptionKey, {iv: iv});

    return decrypted.toString(Utf8);
  }

  this.timeBytes = function timeBytes(time){
    if(time){
      time = (time / 1000)
    }else{
      time = (Math.round(new Date() / 1000) + this.ttl)
    }
    var hexTime = time.toString(16).lpad('0', '16')
    return Hex.parse(hexTime);
  }

  this.createToken = function(signingKey, time, iv, cipherText){
    var hmac = this.createHmac(signingKey, time, iv, cipherText);
    var tokenWords = Hex.parse(this.versionHex);
    tokenWords = tokenWords.concat(time);
    tokenWords = tokenWords.concat(iv);
    tokenWords = tokenWords.concat(cipherText);
    tokenWords = tokenWords.concat(hmac);
    return urlsafe(tokenWords.toString(Base64));
  }

  this.createHmac = function createHmac(signingKey, time, iv, cipherText) {
    var hmacWords = Hex.parse(this.versionHex);
    hmacWords = hmacWords.concat(time);
    hmacWords = hmacWords.concat(iv);
    hmacWords = hmacWords.concat(cipherText);
    return HmacSHA256(hmacWords, signingKey);
  }

  this.token = function token(message, time){
    if(!this.iv) this.setIV(opts.iv);
    if(!this.secret) throw("Secret not set");
    var cipherText = this.encryptMessage(message,
        this.secret.encryptionKey, this.iv);
    var now = this.timeBytes(time);
    var token = this.createToken(this.secret.signingKey,
        now, this.iv, cipherText)
    return token;
  }

  this.decode = function(token){
    var t = {}
    var tokenString = decode64toHex(token);
    var versionOffset = hexBits(8);
    var timeOffset    = versionOffset + hexBits(64);
    var ivOffset      = timeOffset + hexBits(128);
    var hmacOffset = tokenString.length - hexBits(256);
    t.version   = parseHex(tokenString.slice(0,versionOffset));
    var timeInt = parseHex(tokenString.slice(versionOffset, timeOffset));
    t.time      = new Date(timeInt * 1000);
    t.iv        = tokenString.slice(timeOffset, ivOffset);
    t.cipherText = tokenString.slice(ivOffset, hmacOffset);
    t.message    = this.decryptMessage(Hex.parse(t.cipherText), this.secret.encryptionKey, Hex.parse(t.iv))
    t.hmacHex    = tokenString.slice(hmacOffset);
    var computedHmac = this.createHmac(this.secret.signingKey, this.timeBytes(t.time), Hex.parse(t.iv), Hex.parse(t.cipherText));
    t.computedHmacHex = computedHmac.toString(Hex);
    return t;
  }
}

exports = module.exports = fernet;
fernet.call(exports)
