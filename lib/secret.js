var f = require('../fernet');

var Secret = function (secret64) {
  var secret = f.decode64toHex(secret64);
  if (secret.length !== f.hexBits(256)) {
    throw new Error('Secret must be 32 url-safe base64-encoded bytes.');
  }
  this.signingKeyHex = secret.slice(0, f.hexBits(128));
  this.signingKey = f.Hex.parse(this.signingKeyHex);
  this.encryptionKeyHex = secret.slice(f.hexBits(128));
  this.encryptionKey = f.Hex.parse(this.encryptionKeyHex);
}

exports = module.exports = Secret;
