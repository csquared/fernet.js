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

suite('Generate a Token', function(){

  test('token matches', function(){
    var message = testData.src;
    fernet.setSecret(testData.secret);
    fernet.setIV(testData.iv);
    var token = fernet.token(message, Date.parse(testData.now));
    assert.equal(testData.token, token);
  })

  test("works as new object", function(){
    var message = testData.src;
    var f = new fernet({secret: testData.secret, iv: testData.iv})
    var token = f.token(message, Date.parse(testData.now));
    assert.equal(testData.token, token);
  })

})
