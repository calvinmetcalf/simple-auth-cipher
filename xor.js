module.exports = xor;
function xor(a, b){
  var len = Math.min(a.length, b.length);
  var out = new Buffer(len);
  var i = -1;
  while (++i <  len) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}