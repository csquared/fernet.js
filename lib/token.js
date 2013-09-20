var fernet = require('../fernet');

var Token = function Token(opts){
  opts = opts || {};
  this.secret     = opts.secret || Token.parent.secret;
  this.message    = opts.message;
  this.cipherText = opts.cipherText;
  this.token      = opts.token;
  this.version    = opts.version || fernet.parseHex(fernet.versionHex);
  this.optsIV     = opts.iv;
  if(opts.time) this.setTime(Date.parse(opts.time));
}

Token.prototype = {
  setIV: fernet.setIV,
  setTime: function(time){
    this.time = fernet.timeBytes(time);
  },
  toString: function(){
    if(this.encoded){
      return this.token
    }else{
      return this.message
    }
  },
  encode: function(message){
    if(!this.secret) throw(new Error("Secret not set"));
    this.encoded = true;
    this.setIV(this.optsIV);  //if null will always be a fresh IV
    this.message = message || this.message;
    this.cipherText = fernet.encryptMessage(this.message, this.secret.encryptionKey, this.iv);
    this.token = fernet.createToken(this.secret.signingKey,this.time, this.iv, this.cipherText)
    return this.token;
  },
  decode: function(token){
    if(!this.secret) throw(new Error("Secret not set"));
    this.encoded = false;
    this.token = token || this.token;

    var tokenString   = fernet.decode64toHex(this.token);
    var versionOffset = fernet.hexBits(8);
    var timeOffset    = versionOffset + fernet.hexBits(64);
    var ivOffset      = timeOffset + fernet.hexBits(128);
    var hmacOffset    = tokenString.length - fernet.hexBits(256);
    var timeInt       = fernet.parseHex(tokenString.slice(versionOffset, timeOffset));

    this.version  = fernet.parseHex(tokenString.slice(0,versionOffset));
    this.time     = new Date(timeInt * 1000);
    this.ivHex    = tokenString.slice(timeOffset, ivOffset);
    this.iv       = fernet.Hex.parse(this.ivHex);
    this.cipherTextHex = tokenString.slice(ivOffset, hmacOffset);
    this.cipherText = fernet.Hex.parse(this.cipherTextHex);
    this.hmacHex    = tokenString.slice(hmacOffset);

    var computedHmac = fernet.createHmac(this.secret.signingKey, fernet.timeBytes(this.time), this.iv, this.cipherText);
    this.message     = fernet.decryptMessage(this.cipherText, this.secret.encryptionKey, this.iv)
    return this.message;
  }
}

exports = module.exports = Token;
