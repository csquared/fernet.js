var CryptoJS = require('crypto-js/core');
var AES    = require('crypto-js/aes');
var Utf8   = require('crypto-js/enc-utf8');
var Latin1 = require('crypto-js/enc-latin1');
var Hex = require('crypto-js/enc-hex');
var Base64 = require('crypto-js/enc-base64');
var HmacSHA256 = require('crypto-js/hmac-sha256');
var URLBase64 = require('urlsafe-base64');

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


var decode64toHex = function decode64(string){
  var s = URLBase64.decode(string.replace(/=+$/, ''));
  return (new Buffer(s)).toString('hex');
}

String.prototype.lpad = function(padString, length) {
  var str = this;
  while (str.length < length) str = padString + str;
  return str;
}

var fernet = function fernet(opts){
  this.Hex = Hex;

  //Sets the secret from base64 encoded value
  this.setSecret = function setSecret(secret64){
    this.secret = new this.Secret(secret64);
    return this.secret;
  }

  this.Secret = function(secret64){
    var secret = decode64toHex(secret64);
    this.signingKeyHex = secret.slice(0,hexBits(128));
    this.signingKey = Hex.parse(this.signingKeyHex);
    this.encryptionKeyHex = secret.slice(hexBits(128));
    this.encryptionKey = Hex.parse(this.encryptionKeyHex);
  }

  var ArrayToHex = function ArrayToHex(array){
    hex = '';
    for( var _byte in array){
      hex += Number(_byte).toString(16).lpad('0',2);
    }
    return hex;
  }
  this.ArrayToHex = ArrayToHex;

  var setIV = function setIV(iv_array){
    if(iv_array){
      this.ivHex = ArrayToHex(iv_array);
      this.iv = Hex.parse(this.ivHex);
    }else{
      this.iv = CryptoJS.lib.WordArray.random(128/8);
      this.ivHex = this.iv.toString(Hex);
    }
    return this.ivHex;
  }
  this.setIV = setIV;

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

  var timeBytes = function timeBytes(time){
    if(time){
      time = (time / 1000)
    }else{
      time = (Math.round(new Date() / 1000) + this.ttl)
    }
    var hexTime = time.toString(16).lpad('0', '16')
    return Hex.parse(hexTime);
  }

  this.timeBytes = timeBytes;

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

  /*
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
  */

  var self = this;
  this.Token = function Token(opts){
    opts = opts || {};
    this.secret     = opts.secret || self.secret;
    this.message    = opts.message;
    this.cipherText = opts.cipherText;
    this.token      = opts.token;
    this.version    = opts.version || parseHex(self.versionHex);
    this.optsIV     = opts.iv;
    if(opts.time) this.setTime(Date.parse(opts.time));
  }

  this.Token.prototype = {
    setIV: setIV,
    setTime: function(time){
      this.time = timeBytes(time);
    },
    toString: function(){
      if(this.encoded){
        return this.token
      }else{
        return this.message
      }
    },
    encode: function(message){
      this.encoded = true;
      if(!this.secret) throw("Secret not set");
      this.setIV(this.optsIV);  //if null will always be a fresh IV
      this.message = message || this.message;
      this.cipherText = self.encryptMessage(this.message, this.secret.encryptionKey, this.iv);
      this.token = self.createToken(this.secret.signingKey,this.time, this.iv, this.cipherText)
      return this.token;
    },

    decode: function(token){
      this.encoded = false;
      this.token = token || this.token;

      var tokenString   = decode64toHex(this.token);
      var versionOffset = hexBits(8);
      var timeOffset    = versionOffset + hexBits(64);
      var ivOffset      = timeOffset + hexBits(128);
      var hmacOffset    = tokenString.length - hexBits(256);
      var timeInt       = parseHex(tokenString.slice(versionOffset, timeOffset));

      this.version  = parseHex(tokenString.slice(0,versionOffset));
      this.time     = new Date(timeInt * 1000);
      this.ivHex    = tokenString.slice(timeOffset, ivOffset);
      this.iv       = Hex.parse(this.ivHex);
      this.cipherTextHex = tokenString.slice(ivOffset, hmacOffset);
      this.cipherText = Hex.parse(this.cipherTextHex);
      this.hmacHex    = tokenString.slice(hmacOffset);

      //var computedHmac = self.createHmac(this.secret.signingKey, this.time, this.iv, this.cipherText);
      this.message   = self.decryptMessage(this.cipherText, this.secret.encryptionKey, this.iv)
      return this.message;
    }
  }

}

/*
fernet.prototype = {
  decode: function(token){
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
*/

exports = module.exports = fernet;
fernet.call(exports)
