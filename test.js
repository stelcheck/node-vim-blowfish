
var crypto  = require('crypto');
var fs      = require('fs');


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
exports.getKey = getKey;


function flipEndian(inData) {
	var bLen = inData.length;
	var outData = new Buffer(bLen);

	for (var i=0; i<bLen; i+=4) {
        outData.writeUInt32BE(inData.readUInt32LE(i), i);
	}
	return outData;
}
exports.flipEndian = flipEndian;


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
exports.repeatBuffer = repeatBuffer;


function decrypt(binKey, iv, contents) {
    /**
     * Decryption process
     */
    var bf = crypto.createCipheriv('bf-ecb', binKey, '');

	// Initialize the keystream:
	iv_be = repeatBuffer(flipEndian(iv), 8);
	var keystream_be = new Buffer(bf.update(iv_be, 'binary'), 'binary');
	var keystream = flipEndian(keystream_be);

	var blockLen = keystream.length;
	if (blockLen !== 64) {
		console.log('WARNING:  expecting a blockLen of 64 bytes...');
	}

	var cLen = contents.length;
	var cPos = 0;
	var output = new Buffer(cLen);

	var numBlocks = Math.ceil(cLen / blockLen);

	for (var blockNumber=0; blockNumber < numBlocks; blockNumber++) {
		var remainingBytes = cLen - 1 - cPos;
		var thisBlockLen = Math.min(blockLen, remainingBytes);
		for (var i=0; i<thisBlockLen; i++) {
			cPos = blockNumber * blockLen + i;
			output[cPos] = keystream[i] ^ contents[cPos];
		}
		if (cPos >= cLen) {
			break;
		}
		var newSeed = flipEndian(contents.slice(cPos-blockLen+1, cPos+1));
		keystream = flipEndian(new Buffer(bf.update(newSeed, 'binary'), 'binary'));
	}
	return output;
}
exports.decrypt = decrypt;


function decryptFile(filename, password) {
	var data    = fs.readFileSync(filename);

	var header = data.slice(0, 12);
	if (header.toString() == 'VimCrypt~02!') {
		var salt = data.slice(12,20);
		var iv   = data.slice(20,28);
		var contents = data.slice(28);

		var key = getKey(password, salt);
		console.log(' key: ', key);
		var binKey = new Buffer(key, 'hex');

		return decrypt(binKey, iv, contents);
	} else {
		console.log('Cannot read file.  Only VimCrypt-2 is supported.');
		return;
	}
}
exports.decryptFile = decryptFile;



/**
 *  usage:  decryptFile(filename, password)
 */

var output = decryptFile('const.txt', 'test');
console.log(output.toString());

