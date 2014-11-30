var through2 = require('through2');
var crypto = require('crypto');
var xor = require('./xor');
var modes = {
  16: 'aes-128-ctr',
  24: 'aes-192-ctr',
  32: 'aes-256-ctr'
}
module.exports = decrypt;
function decrypt(key, iv, aad) {
  iv = Buffer.concat([iv, new Buffer([0,0,0,0])]);
  var mode = modes[key.length];
  var cipher = crypto.createDecipheriv(mode, key, iv);
  var hmacKey = new Buffer(32);
  hmacKey.fill(0);
  var tagCipher = new Buffer(32);
  tagCipher.fill(0);
  // this works because decrypt and encrypt are the same for ctr
  var hmac = crypto.createHmac('sha256', cipher.update(hmacKey));
  tagCipher = cipher.update(tagCipher);
  aad = aad || new Buffer('');
  hmac.update(aad);
  var cache = new Buffer('');
  return through2(function (data, _, next) {
    cache = Buffer.concat([cache, data]);
    next();
  }, function (next) {
    var tag = cache.slice(-32);
    tag = xor(tag, tagCipher);
    cache = cache.slice(0, -32);
    var len = cache.length;
    hmac.update(cache);
    // encode both the data lengths
    var lenBuffer = new Buffer(64);
    lenBuffer.fill(0);
    lenBuffer.writeUInt32BE(aad.length, 0);
    lenBuffer.writeUInt32BE(len, 4);
    hmac.update(lenBuffer);
    // create that tag
    var ourTag = hmac.digest();
    var dif = 0;
    var i = -1;
    while (++i < 32) {
      dif += ourTag[i] ^ tag[i];
    }
    if (dif) {
      return next(new Error('unble to match tag'))
    }
    this.push(cipher.update(cache));
    cipher.final();
    next()
  });
}