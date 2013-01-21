var _0x100000000000000 = 0x100000000000000,
    _0x1000000000000 =     0x1000000000000,
    _0x10000000000 =         0x10000000000,
    _0x100000000 =             0x100000000,
    _0x1000000 =                 0x1000000,
    _0x10000 =                     0x10000,
    _0x100 =                         0x100,
    _0xff =                           0xff,
    _0x80 =                           0x80;

function toArray( buffer ){
    var len = buffer.length;
    var ret = [];
    for (var i = len-1; i >= 0; i--) {
        ret.push(buffer[i]);
    }
    return ret;
};
    
function decodeInt64(buffer, offset, endian) {
    var isBigEndian = endian == 'big',
        _buffer = buffer.slice(offset, offset + 8),
        bytes = toArray(_buffer),
        rv = 0,  
        overflow = 0;
    isBigEndian && bytes.reverse();
    // avoid overflow
    if (bytes[0] & _0x80) {

        ++overflow;
        bytes[0] ^= _0xff;
        bytes[1] ^= _0xff;
        bytes[2] ^= _0xff;
        bytes[3] ^= _0xff;
        bytes[4] ^= _0xff;
        bytes[5] ^= _0xff;
        bytes[6] ^= _0xff;
        bytes[7] ^= _0xff;
    }
    rv += bytes[0] * _0x100000000000000;
    rv += bytes[1] *   _0x1000000000000;
    rv += bytes[2] *     _0x10000000000;
    rv += bytes[3] *       _0x100000000;
    rv += bytes[4] *         _0x1000000;
    rv += bytes[5] *           _0x10000;
    rv += bytes[6] *             _0x100;
    rv += bytes[7];

    if (overflow) {
        rv += 1;
        rv *= -1;
    }
    return rv;
}

function encodeInt64(buffer, number, offset, endian) {
    var isBigEndian = endian == 'big',
        high = Math.floor(number / _0x100000000),
        low = number & (_0x100000000 - 1),
        ret = [ low & _0xff,
                (low  >>  8) & _0xff,
                (low  >> 16) & _0xff,
                (low  >> 24) & _0xff,
                high & _0xff,
                (high >>  8) & _0xff,
                (high >> 16) & _0xff,
                (high >> 24) & _0xff
              ];
    isBigEndian && ret.reverse();
    var _buffer = new Buffer(ret);
    _buffer.copy(buffer, offset);
    return buffer;
}

exports.readUInt64 = decodeInt64;
exports.writeUInt64 = encodeInt64;

//example:
//var buf = new Buffer(8);
//encodeInt64(buf, 5911912807, 0, 'little');
//console.log(buf);
// print <Buffer 67 a1 60 60 01 00 00 00>

//var integer = decodeInt64(buf, 0, 'little');
//console.log('integer: ' + integer);
// print 5911912807
