/** support legacy with a fernet() constructor, will create a scoped instance of a fernet wrapper */
class fernet {
  /**
   * creates an instance of a fernet wrapper, where options can be passed in and scoped to this instance.
   * @param {TokenOptions} opts - options for standalone instance of fernet wrapper
   */
  constructor(opts=null){
    // default to 'defaults'
    this.opts = opts || Object.assign({}, defaults);
    this.Secret = Secret;

    // do setup
    this.ivHex = setIV(this.opts.iv);
    this.iv = Hex.parse(this.ivHex);  //if null will always be a fresh IV
    this.ttl = opts.ttl || 60;
    // because (0 || x) always equals x
    if(opts.ttl === 0) this.ttl = 0;
    if (opts.secret){
      this.secret = new Secret(opts.secret);
    }
      
  }

  Token(){
    console.log('THIS IS: ', this)
    console.log('this.json: ', JSON.stringify(this, null, 2))
    return new Token(this);
  }
}