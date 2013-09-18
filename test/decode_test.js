//for browser compatibility
if(!chai)   var chai = require('chai');
if(!fernet) var fernet = require('../fernet');

var assert = chai.assert;

var testData = {
  "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
  "now": "1985-10-26T01:20:00-07:00",
  "iv": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  "src": "hello",
  "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
}

suite('Decode a Token', function(){
  test('recovers version', function(){
    var f = new fernet({secret: testData.secret});
    var token = f.decode(testData.token);
    assert.equal(token.version, 128);
  })

  test('recovers time', function(){
    var f = new fernet({secret: testData.secret});
    var token = f.decode(testData.token);
    var now = new Date(Date.parse(testData.now));
    assert.equal(token.time.toUTCString(), now.toUTCString());
  })

  test('recovers iv', function(){
    var f = new fernet({secret: testData.secret});
    var ivHex = f.setIV(testData.iv);
    var token = f.decode(testData.token);
    assert.equal(token.iv, ivHex);
  })

  test('recovers message', function(){
    var f = new fernet({secret: testData.secret});
    var token = f.decode(testData.token);
    var message = testData.src;
    assert.equal(token.message, message);
  })

  test('checks hmac', function(){
    var f = new fernet({secret: testData.secret});
    var t = f.decode(testData.token);
    var computedHmac = f.createHmac(f.secret.signingKey, f.timeBytes(t.time), f.Hex.parse(t.iv), f.Hex.parse(t.cipherText));
    assert.equal(t.hmacHex, computedHmac.toString(f.Hex));
  })
})

