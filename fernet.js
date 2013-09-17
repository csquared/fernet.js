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

  //Makes a Base64 string a url-safe base64 string
  var urlsafe = function urlsafe(string){
    return string.replace(/\+/g, '-').replace(/\//g, '_') //.replace(/=+$/, '')
  }

  //Sets the secret from base64 encoded value
  this.setSecret = function setSecret(secret64){
    var s = URLBase64.decode(secret64.replace(/=+$/, ''));
    var secret = (new Buffer(s)).toString('hex');
    this.signingKey = Hex.parse(secret.slice(0,32));
    this.encryptionKey = Hex.parse(secret.slice(32));
    return secret;
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
    return 'foo'
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
    if(!this.encryptionKey) throw("Secret not set-- missing encryption key");
    if(!this.signingKey)    throw("Secret not set-- missing signing key");
    var cipherText = this.encryptMessage(message, this.encryptionKey, this.iv);
    var now = this.timeBytes(time);
    var token = this.createToken(this.signingKey, now, this.iv, cipherText)
    return token;
  }
}

exports = module.exports = fernet;
fernet.call(exports)
