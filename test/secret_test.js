//for browser compatibility
var Hex = require('crypto-js/enc-hex');
if(!chai)   var chai = require('chai');
if(!fernet) var fernet = require('../../fernet.js');
var assert = chai.assert;


suite('fernet.Secret', function(){

  var secret64 = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=";
  var signingKeyHex = '730ff4c7af3d46923e8ed451ee813c87';
  var encryptionKeyHex = 'f790b0a226bc96a92de49b5e9c05e1ee';
  var secret = new fernet.Secret(secret64);

  test('secret.signingKeyHex', function(){
    assert.equal(secret.signingKeyHex, signingKeyHex);
  })

  test('secret.signingKey', function(){
    // changed to equal because they were both the same, but would fail deepEqual?
    assert.equal(JSON.stringify(secret.signingKey), JSON.stringify(Hex.parse(signingKeyHex)));
  })

  test('secret.encryptionKeyHex', function(){
    assert.equal(secret.encryptionKeyHex, encryptionKeyHex);
  })

  test('secret.encryptionKey', function(){
    // changed to equal because they were both the same, but would fail deepEqual?
    assert.equal(JSON.stringify(secret.encryptionKey), JSON.stringify(Hex.parse(encryptionKeyHex)));
  })

  test('raises "new Error(\'Secret must be 32 url-safe base64-encoded bytes.\')" on wrong secret', function(){

    assert.throws(function(){
      new fernet.Secret('not a good secret');
    }, Error, 'Secret must be 32 url-safe base64-encoded bytes.');
  })

})
