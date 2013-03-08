// bf             bf-cbc         bf-cfb
// bf-ecb         bf-ofb
var crypto  = require('crypto');
var fs      = require('fs');
var data    = fs.readFileSync('file');
var pass    = 'test';

var header = data.slice(0, 12);
var isEncrypted = header.toString() === 'VimCrypt~02!';


function getKey(password, salt) {
    var hash = crypto.createHash('sha256');

	hash.update(password);
	hash.update(salt);

	var key = hash.digest('hex');

    /* Process the key 1000 times.
        See http://en.wikipedia.org/wiki/Key_strengthening */

	for (var i=0; i<1000; i++) {
		hash = crypto.createHash('sha256');
		hash.update(key);
		hash.update(salt);
		key = hash.digest('hex');
	}

	return key;
}


function flipEndian(inData) {
	var bLen = inData.length;
	var outData = new Buffer(bLen);

	for (var i=0; i<bLen; i+=4) {
        outData.writeUInt32BE(inData.readUInt32LE(i), i);
	}
	return outData;
}


function repeatBuffer(inBuffer, n) {
	var inLen = inBuffer.length;
	var outLen = inLen * n;
	out = new Buffer(outLen);

	for (var i = 0; i<n; i++) {
		for (var j=0; j<inLen; j++) {
			out[ i * inLen + j] = inBuffer[j];
		}
	}
	return out;
}


if (isEncrypted) {
    var salt = data.slice(12,20);
    var iv   = data.slice(20,28);
	var contents = data.slice(28);

    var key = getKey(pass, salt);
	console.log(' key: ', key);
	var binKey = new Buffer(key, 'hex');

    /**
     * Decryption process
     */
    var bf = crypto.createCipheriv('bf-ecb', binKey, '');


	//   ****************
	// TODO:  FIXME:  This only decrypts the first block
	//   ****************

	// Initialize the keystream:
	iv_be = repeatBuffer(flipEndian(iv), 8);
	var keystream_be = new Buffer(bf.update(iv_be, 'binary'), 'binary');
	var keystream = flipEndian(keystream_be);

    console.log('\n    ****  Decrypting ONLY the first block:');

	var blockLen = 64;
	blockLen = Math.min(blockLen, keystream.length);
	blockLen = Math.min(blockLen, contents.length);

	var output = new Buffer(blockLen);
    for (var i=0; i<blockLen; i++) {
		output[i] = keystream[i] ^ contents[i];
	}

	console.log(output.toString());
}


