var test = require('tape');
var as = require('./');
var through2 = require('through2');

test('first', function (t) {
	t.plan(1);
	var message = 'hello there, how are you, my name is calvin'.split(' ').map(function (word) {
		return new Buffer(word + ' ');
	});
	var key = new Buffer(16);
	key.fill(0);
	var iv = new Buffer(12);
	iv.fill(0);
	var out = '';
	var ad = new Buffer('good bye nice person');
	var encrypter = as.encrypt(key, iv, ad);
	var decrypter = as.decrypt(key, iv, ad);
	decrypter.on('data', function (d) {
		out += d.toString();
	}).on('end', function () {
		t.equals(out, 'hello there, how are you, my name is calvin ');
	});
	encrypter.pipe(decrypter);
	message.forEach(function (word) {
		encrypter.write(word);
	});
	encrypter.end();
})