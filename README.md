# Fernet.js

Javascript implementation of <a href="https://github.com/kr/fernet-spec">Fernet symmetric encryption</a>.

Fernet is an opinionated way of using AES and HMAC authentication that makes
shared-secret symmetric encryption simpler for communicating applications.

Fernet.js combines Crypto-JS, sjcl, and browserify to provide a library that works
in both node and the browser.

Instead of using TypedArrays I use Hex Strings and CryptoJS's `Hex.parse`
to build up `CryptoJs.lib.WordArray` objects.  The Stanford Javscript Crypto
Library is used for pseudo-random number generation.

## WARNING

[It's generally *never* considered safe to encrypt data in the browser.](http://www.matasano.com/articles/javascript-cryptography/)

However, you can use this library to encrypt/decrypt data server-side and decrypt data on a client.

## Use

### node.js
```javascript
var fernet = require('./fernet');
```

### browser
```html
<script src="fernetBrowser.js"></script>
```


## Fernet

### fernet.setSecret(string)

Sets the `secret` at the top level for all further Tokens made
from this instance of Fernet.

### fernet.ttl = seconds

Sets the `ttl` at the top level for all further Tokens made
from this instance of Fernet.

## Secret

### new fernet.Secret(string)

```javascript
  var secret = new fernet.Secret("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
  /*
    {
      signingKeyHex: '730ff4c7af3d46923e8ed451ee813c87',
      signingKey: [CryptoJS.lib.WordArray],
      encryptionKeyHex: 'f790b0a226bc96a92de49b5e9c05e1ee',
      encryptionKey: [CryptoJS.lib.WordArray]
    }
  */
```

## Token

## new fernet.Token(options)

Options:

- `secret`: a `fernet.Secret` object
- `token`: a Fernet-encoded String
- `ttl`: seconds of ttl

For testing:

- `time`: Date object
- `iv`: Array of Integers

### Token.prototype.encode
```javascript
//Have to include time and iv to make it deterministic.
//Normally time would default to (new Date()) and iv to something random.
var token = new fernet.Token({
  secret: secret,
  time: Date.parse(1),
  iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
})
token.encode("Message")
/*
'gAAAAABSO_yhAAECAwQFBgcICQoLDA0OD1PGoFV6wgWZG6AOBfQqevwJT2qKtCZ0EjKy1_TvyxTseR_3ebIF6Ph-xa2QT_tEvg=='
*/
```

### Token.prototype.decode
Include tt
```javascript
var token = new fernet.Token({
  secret: secret,
  token: 'gAAAAABSO_yhAAECAwQFBgcICQoLDA0OD1PGoFV6wgWZG6AOBfQqevwJT2qKtCZ0EjKy1_TvyxTseR_3ebIF6Ph-xa2QT_tEvg==',
  ttl: 0
})
token.decode();

/*
"Message"
*/
```

## Test

    > npm test

Compiles new fernetBrowser.js via `browserify`,
tests node lib with `mocha`, then opens test.html via `open`.
