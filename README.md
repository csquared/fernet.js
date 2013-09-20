# Fernet.js

Javascript implementation of <a href="https://github.com/kr/fernet-spec">Fernet symmetric encryption</a>.

Fernet is an opinionated way of using AES and HMAC authentication that makes
shared-secret symmetric encryption simpler for communicating applications.

Fernet.js combines Crypto-JS and browserify to provide a library that works
in both node and the browser.

Instead of using TypedArrays I use Hex Strings and CryptoJS's `Hex.parse`
to build up `CryptoJs.lib.WordArray` objects.

## Use

### node.js
```javascript
var fernet = require('./fernet');
```

### browser
```html
<script src="fernetBrowser.js"></script>
```


## fernet.Secret

```javascript
  var secret = new fernet.Secret("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
  /*
    {
      signingKeyHex: '730ff4c7af3d46923e8ed451ee813c87',
      signingKey: [CryptoJS.lib.WordArray],
      encryptionKeyHex: 'f790b0a226bc96a92de49b5e9c05e1ee',
      encryptionKey: [CryptoJS.lib.WordArray]
    }
```


## fernet.Token

```javascript
var token = new fernet.Token({secret: secret, time: Date.parse(1), iv: fernet.Hex.parse('00010203040506070809100a0b0c0d0e')})
token.encode("Message")
/*
  'gAAAAABSO_b6AAAKAAAKAAAKAAAKAAAKAAAKTNL-BGNCVRFOKEAv2JKj3z7Vpp-kw2Ddp6zrsZazimQ0dCUscYLYoZCv2kMw2mHw'
*/



``



