var CryptoJS = require('crypto-js/core');
var AES = require('crypto-js/aes');
var Utf8 = require('crypto-js/enc-utf8');
var Latin1 = require('crypto-js/enc-latin1');
var Hex = require('crypto-js/enc-hex');
var Base64 = require('crypto-js/enc-base64');
var HmacSHA256 = require('crypto-js/hmac-sha256');
var URLBase64 = require('urlsafe-base64');
var crypto = require('crypto');

//lpad a string for some hex conversions
String.prototype.lpad = function (padString, length) {
  var str = this;
  while (str.length < length) str = padString + str;
  return str;
}

//Makes a Base64 string a url-safe base64 string
var urlsafe = function urlsafe(string) {
  return string.replace(/\+/g, '-').replace(/\//g, '_') //.replace(/=+$/, '')
}

// parse a Hex string to an Int
var parseHex = function parseHex(hexString) {
  return parseInt('0x' + hexString);
}

// turn bits into number of chars in a hex string
var hexBits = function hexBits(bits) {
  return bits / 8 * 2;
}

// convert base64 string to hex string
var decode64toHex = function decode64(string) {
  var s = URLBase64.decode(string.replace(/=+$/, ''));
  return (new Buffer(s)).toString('hex');
}

// convert array to hex string
var ArrayToHex = function ArrayToHex(array) {
  var hex = '';
  for (var _byte in array) {
    hex += Number(_byte).toString(16).lpad('0', 2);
  }
  return hex;
}

var randomHex = function (size) {
  return crypto.randomBytes(128 / 8).toString('hex')
}

var setIV = function setIV(iv_array) {
  if (iv_array) {
    this.ivHex = ArrayToHex(iv_array);
  } else {
    this.ivHex = randomHex(128 / 8);
  }
  this.iv = Hex.parse(this.ivHex);
  return this.ivHex;
}

//convert Time object or now into WordArray
var timeBytes = function timeBytes(time) {
  if (time) {
    time = (time / 1000)
  } else {
    time = (Math.round(new Date() / 1000))
  }
  var hexTime = time.toString(16).lpad('0', '16')
  return Hex.parse(hexTime);
}


var fernet = function fernet(opts) {
  this.Hex = Hex;
  this.Base64 = Base64;
  this.parseHex = parseHex;
  this.decode64toHex = decode64toHex;
  this.hexBits = hexBits;
  this.urlsafe = urlsafe;

  //Sets the secret from base64 encoded value
  this.setSecret = function setSecret(secret64) {
    this.secret = new this.Secret(secret64);
    return this.secret;
  }

  this.ArrayToHex = ArrayToHex;
  this.setIV = setIV;

  this.encryptMessage = function (message, encryptionKey, iv) {
    var encrypted = AES.encrypt(message, encryptionKey, { iv: iv });
    return encrypted.ciphertext;
  }

  this.decryptMessage = function (cipherText, encryptionKey, iv) {
    var encrypted = {};
    encrypted.key = encryptionKey;
    encrypted.iv = iv;
    encrypted.ciphertext = cipherText;

    var decrypted = AES.decrypt(encrypted, encryptionKey, { iv: iv });

    return decrypted.toString(Utf8);
  }

  this.timeBytes = timeBytes;

  this.createToken = function (signingKey, time, iv, cipherText) {
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

  this.Secret = require('./lib/secret');
  this.Token = require('./lib/token')(this);

  opts = opts || {};
  this.ttl = opts.ttl || 60;
  // because (0 || x) always equals x
  if (opts.ttl === 0) this.ttl = 0;
  this.versionHex = '80';
  this.setIV(opts.iv);
  if (opts.secret) { this.setSecret(opts.secret) }
}

exports = module.exports = fernet;
fernet.call(exports)
