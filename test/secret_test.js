//for browser compatibility
if (!chai) var chai = require('chai');
if (!fernet) var fernet = require('../fernet');
var assert = chai.assert;


describe('fernet.Secret', function () {

  var secret64 = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=";
  var signingKeyHex = '730ff4c7af3d46923e8ed451ee813c87';
  var encryptionKeyHex = 'f790b0a226bc96a92de49b5e9c05e1ee';
  var secret = new fernet.Secret(secret64);

  it('secret.signingKeyHex', function () {
    assert.equal(secret.signingKeyHex, signingKeyHex);
  });

  it('secret.signingKey', function () {
    assert.deepEqual(secret.signingKey, fernet.Hex.parse(signingKeyHex));
  });

  it('secret.encryptionKeyHex', function () {
    assert.equal(secret.encryptionKeyHex, encryptionKeyHex);
  });

  it('secret.encryptionKey', function () {
    assert.deepEqual(secret.encryptionKey, fernet.Hex.parse(encryptionKeyHex));
  });

  it('raises "new Error(\'Secret must be 32 url-safe base64-encoded bytes.\')" on wrong secret', function () {

    assert.throws(function () {
      new fernet.Secret('not a good secret');
    }, Error, 'Secret must be 32 url-safe base64-encoded bytes.');
  })

});
