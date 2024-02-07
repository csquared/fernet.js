# Fernet.js

![ci status](https://github.com/csquared/fernet.js/actions/workflows/node.js.yml/badge.svg?branch=master)

Javascript implementation of <a href="https://github.com/kr/fernet-spec">Fernet symmetric encryption</a>.

Fernet is an opinionated way of using AES and HMAC authentication that makes
shared-secret symmetric encryption simpler for communicating applications.

Fernet.js uses browserify to provide a library that works
in both node and the browser.

Instead of using TypedArrays I use Hex Strings and CryptoJS's `Hex.parse`
to build up `CryptoJs.lib.WordArray` objects.

## WARNING

[It's generally *never* considered safe to encrypt data in the browser.](http://www.matasano.com/articles/javascript-cryptography/)

However, you can use this library to encrypt/decrypt data server-side and decrypt data on a client.

That being said, the only randomness used by this library without your control is a call to `crypto.randomBytes` to generate IVs.
This function defaults to OpenSSL server-side and [browserify's random number generator implementation](https://github.com/crypto-browserify/crypto-browserify/blob/master/index.js)
client-side.  The browserify implementation only uses real browser crypto or throws an error. (IE: no calls to `Math.random()`)

If you're planning on generating the secrets in the browser do yourself a favor and get an audit.

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

### Generating a secret

    Generating appropriate secrets is beyond the scope of `Fernet`, but you should
    generate it using `/dev/random` in a *nix. To generate a base64-encoded 256 bit
    (32 byte) random sequence, try:

    dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64

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
