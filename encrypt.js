var through2 = require('through2');
var crypto = require('crypto');
var xor = require('./xor');
var modes = {
     16: 'aes-128-ctr',
     24: 'aes-192-ctr',
     32: 'aes-256-ctr'
}
module.exports = encrypt;

function encrypt(key, iv, aad) {
  iv = Buffer.concat([iv, new Buffer([0,0,0,0])]);
  var mode = modes[key.length];
  var cipher = crypto.createCipheriv(mode, key, iv);
  // if it wasn't an example, instead of letting the user choose the mode
  // we could figure out if it was aes-128/192/256 from key length
  // just choose the appropriate ctr mode
  // this assumes ctr mode
  var hmacKey = new Buffer(32);
  hmacKey.fill(0);
  var hmac = crypto.createHmac('sha256', cipher.update(hmacKey));
  var tagCipher = new Buffer(32);
  tagCipher.fill(0);
  tagCipher = cipher.update(tagCipher);
  // encrypt some zeros as the hmac key, this is what 
  // gcm and chacha20/poly1305 both do
  aad = aad || new Buffer('');
  hmac.update(aad);
  var len = 0;
  // this is the total length of data we encrypted
  return through2(function (data, _, next) {
    len += data.length;
    var out = cipher.update(data);

    hmac.update(out);
    this.push(out);
    next();
  }, function (next) {
    // encode both the data lengths
    var lenBuffer = new Buffer(64);
    lenBuffer.fill(0);
    lenBuffer.writeUInt32BE(aad.length, 0);
    lenBuffer.writeUInt32BE(len, 4);
    hmac.update(lenBuffer);
    // create that tag
    var tag = hmac.digest();
    tag = xor(tag, tagCipher);
    cipher.final();
    // If i was doing this not as an example
    // I'd append this to the ciphertext
    // but that would make the decipherer much more complex.
    this.push(tag);
    next()
  });
}

