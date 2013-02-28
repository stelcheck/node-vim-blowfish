// bf             bf-cbc         bf-cfb
// bf-ecb         bf-ofb
var crypto  = require('crypto');
var fs      = require('fs');
var data    = fs.readFileSync('file');
var pass    = 'test';

var isEncrypted = data.slice(0, 12).toString() === 'VimCrypt~02!';

if (isEncrypted) {
    /**
     * We remove the file encryption type identifier, then extract the salt and
     * the IVR
     */
    data = data.slice(12);

    var salt = data.slice(0,8);
    var ivr  = data.slice(8,16);

    data = data.slice(16);
    pass = new Buffer(pass, 'ascii');

    console.log('salt ::', salt.length, salt.toString('hex'));
    console.log('ivr  ::', ivr.length, ivr.toString('hex'));
    console.log('pass ::', pass.length, pass.toString('hex'));

    /**
     * Hashing
     */
    // console.log('\n\nhashing');

    key = sha256_hex(pass, salt);

    for (var i = 0; i < 1000; i++){
        /* if (i < 5) {
            console.log('key  ::', key.length, key.toString('hex'), "(salt: ", salt.toString('hex'), ")");
        } */

        key = sha256_hex(key, salt);
    }

    console.log('\nafter hashing');
    console.log('key  ::', key.length, key.toString('hex'));

    /**
     * Decryption process
     */
    var bf      = crypto.createCipheriv('bf-cfb', key, ivr);

    console.log('\nData to decrypt', data.length);

    console.log(data);

    var store = new Buffer(8), output = new Buffer(0);

    console.log('\nDecrypting blocks');

    for (var j = 0; j < data.length; j += 8) {

        // Change from little little-endian to big-endian
        store.writeUInt32BE(data.readUInt32LE(j), 0);
        store.writeUInt32BE(data.readUInt32LE(j + 4), 4);

        console.log('');
        console.log('convert\t:', data.slice(j, j+8).toString('hex') + '\t', store.length + ':' + store.toString('hex') + '\t');

        // Crypt/decrypt
        res = new Buffer(bf.update(store), 'binary');
        console.log('decrypt\t:', store.toString('hex') + '\t', res.length + ':' + res.toString('hex') + "\t");

        // Change from little little-endian to big-endian
        store.writeUInt32BE(res.readUInt32LE(0), 0);
        store.writeUInt32BE(res.readUInt32LE(4), 4);
        console.log('res\t:', data.slice(j, j+8).toString('hex') + '\t', store.length + ':' + store.toString('hex') + '\t');

        output = Buffer.concat([output, store]);
    }

    output = Buffer.concat([output, new Buffer(bf.final('binary'))]);
}

console.log('');
console.log(data.length + ' bytes crypted\t', data, data.toString());
console.log(output.length + ' bytes decrypted\t', output, output.toString());

var orig = fs.readFileSync('file.decrypted');
console.log(orig.length + ' bytes original\t', orig, orig.toString());

function sha256_hex() {
    var hash = crypto.createHash('sha256');
    var buffers = Array.prototype.slice.call(arguments, 0);

    for (var i = 0; i < buffers.length; i++) {
        hash.update(buffers[i]);
    }

    return hash.digest('hex');
}
