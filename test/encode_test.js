//for browser compatibility
if (!chai) var chai = require('chai');
if (!fernet) var fernet = require('../fernet');

var assert = chai.assert;

var testData = {
  "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
  "now": "1985-10-26T01:20:00-07:00",
  "iv": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  "src": "hello",
  "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
}

suite('fernet.Token', function () {
  test('contains a version', function () {
    var token = new fernet.Token()
    assert.equal(128, token.version)
  })
})


suite('fernet.Token.prototype.encode', function () {
  var secret = new fernet.Secret(testData.secret);

  test("encode(message)", function () {
    var token = new fernet.Token({
      secret: secret,
      iv: testData.iv,
      time: testData.now
    })
    token.encode(testData.src);
    assert.equal(testData.token, token.toString());
  })

  test("token.encode() makes token.toString() return the token", function () {
    var token = new fernet.Token({
      secret: secret,
      iv: testData.iv,
      time: testData.now,
      message: testData.src
    })
    token.encode();
    assert.equal(testData.token, token.toString());
  })

  test("encode() returns the token as a String", function () {
    var token = new fernet.Token({
      secret: secret,
      iv: testData.iv,
      time: testData.now
    })
    assert.equal(token.encode(testData.src), testData.token);
  })

  test("randomly generates IV if one is not passed in", function () {
    var token = new fernet.Token({
      secret: secret,
      time: testData.now
    })
    var tokenString = token.encode(testData.src);
    assert.notEqual(tokenString, testData.token);
    var tokenString2 = token.encode(testData.src);
    assert.notEqual(tokenString, tokenString2);
  })

  test('time defaults to Date.now()', function () {
    var token = new fernet.Token({
      secret: secret
    })
    var cipherText = token.encode('foo');
    var recovered = token.decode(cipherText);
    assert.equal(recovered, 'foo');
  })
})

