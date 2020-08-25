var fernet = require('../fernet');

//TokenFoctory
module = module.exports = function (parent) {
  var Token = function Token(opts) {
    opts = opts || {};
    this.secret = opts.secret || parent.secret;
    this.ttl = opts.ttl || parent.ttl;
    if (opts.ttl === 0) this.ttl = 0;
    this.message = opts.message;
    this.cipherText = opts.cipherText;
    this.token = opts.token;
    this.version = opts.version || fernet.parseHex(parent.versionHex);
    this.optsIV = opts.iv;
    this.maxClockSkew = 60;
    if (opts.time) this.setTime(Date.parse(opts.time));
    else this.setTime();
  }

  Token.prototype = {
    setIV: fernet.setIV,
    setTime: function tokenSetTime(time) {
      this.time = fernet.timeBytes(time);
    },
    toString: function tokenToString() {
      if (this.encoded) {
        return this.token
      } else {
        return this.message
      }
    },
    encode: function encodeToken(message) {
      if (!this.secret) throw (new Error("Secret not set"));
      this.encoded = true;
      this.setIV(this.optsIV);  //if null will always be a fresh IV
      this.message = message || this.message;
      this.cipherText = fernet.encryptMessage(this.message, this.secret.encryptionKey, this.iv);
      this.token = fernet.createToken(this.secret.signingKey, this.time, this.iv, this.cipherText)
      return this.token;
    },
    decode: function decodeToken(token) {
      if (!this.secret) throw (new Error("Secret not set"));
      this.encoded = false;
      this.token = token || this.token;

      var tokenString = fernet.decode64toHex(this.token);
      var versionOffset = fernet.hexBits(8);
      var timeOffset = versionOffset + fernet.hexBits(64);
      var ivOffset = timeOffset + fernet.hexBits(128);
      var hmacOffset = tokenString.length - fernet.hexBits(256);
      var timeInt = fernet.parseHex(tokenString.slice(versionOffset, timeOffset));

      this.version = fernet.parseHex(tokenString.slice(0, versionOffset));

      if (this.version != 128) {
        throw new Error("Invalid version");
      }

      this.time = new Date(timeInt * 1000);

      var currentTime = new Date()
      var timeDiff = (currentTime - this.time) / 1000;

      if (this.ttl > 0) {
        if (timeDiff > this.ttl) {
          throw new Error("Invalid Token: TTL");
        }

        if (((currentTime / 1000) + this.maxClockSkew) < timeInt) {
          throw new Error("far-future timestamp");
        }
      }

      this.ivHex = tokenString.slice(timeOffset, ivOffset);
      this.iv = fernet.Hex.parse(this.ivHex);
      this.cipherTextHex = tokenString.slice(ivOffset, hmacOffset);
      this.cipherText = fernet.Hex.parse(this.cipherTextHex);
      this.hmacHex = tokenString.slice(hmacOffset);
      var decodedHmac = fernet.createHmac(this.secret.signingKey, fernet.timeBytes(this.time), this.iv, this.cipherText);
      var decodedHmacHex = decodedHmac.toString(fernet.Hex);

      var accum = 0
      for (var i = 0; i < 64; i++) {
        accum += decodedHmacHex.charCodeAt(i) ^ this.hmacHex.charCodeAt(i)
      }
      if (accum != 0) throw new Error("Invalid Token: HMAC");

      this.message = fernet.decryptMessage(this.cipherText, this.secret.encryptionKey, this.iv)
      return this.message;
    }
  }

  return Token;
}

//exports = module.exports = Token;
