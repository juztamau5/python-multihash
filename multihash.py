"""Multihash implementation in Python."""

import hashlib
import struct

import six

# Optional SHA-3 hashing via pysha3
try:
    import sha3
except ImportError:
    sha3 = None

# Optional BLAKE2 hashing via pyblake2
try:
    import pyblake2
except ImportError:
    pyblake2 = None


# Constants
IDENTITY = 0X00
MD4 = 0XD4
MD5 = 0XD5
SHA1 = 0X11
SHA2_256 = 0X12
SHA2_512 = 0X13
DBL_SHA2_256 = 0X56
SHA3_224 = 0X17
SHA3_256 = 0X16
SHA3_384 = 0X15
SHA3_512 = 0X14
SHAKE_128 = 0X18
SHAKE_256 = 0X19
KECCAK_224 = 0X1A
KECCAK_256 = 0X1B
KECCAK_384 = 0X1C
KECCAK_512 = 0X1D
MURMUR3_128 = 0X22
MURMUR3_32 = 0X23
BLAKE2B_8 = 0XB201
BLAKE2B_16 = 0XB202
BLAKE2B_24 = 0XB203
BLAKE2B_32 = 0XB204
BLAKE2B_40 = 0XB205
BLAKE2B_48 = 0XB206
BLAKE2B_56 = 0XB207
BLAKE2B_64 = 0XB208
BLAKE2B_72 = 0XB209
BLAKE2B_80 = 0XB20A
BLAKE2B_88 = 0XB20B
BLAKE2B_96 = 0XB20C
BLAKE2B_104 = 0XB20D
BLAKE2B_112 = 0XB20E
BLAKE2B_120 = 0XB20F
BLAKE2B_128 = 0XB210
BLAKE2B_136 = 0XB211
BLAKE2B_144 = 0XB212
BLAKE2B_152 = 0XB213
BLAKE2B_160 = 0XB214
BLAKE2B_168 = 0XB215
BLAKE2B_176 = 0XB216
BLAKE2B_184 = 0XB217
BLAKE2B_192 = 0XB218
BLAKE2B_200 = 0XB219
BLAKE2B_208 = 0XB21A
BLAKE2B_216 = 0XB21B
BLAKE2B_224 = 0XB21C
BLAKE2B_232 = 0XB21D
BLAKE2B_240 = 0XB21E
BLAKE2B_248 = 0XB21F
BLAKE2B_256 = 0XB220
BLAKE2B_264 = 0XB221
BLAKE2B_272 = 0XB222
BLAKE2B_280 = 0XB223
BLAKE2B_288 = 0XB224
BLAKE2B_296 = 0XB225
BLAKE2B_304 = 0XB226
BLAKE2B_312 = 0XB227
BLAKE2B_320 = 0XB228
BLAKE2B_328 = 0XB229
BLAKE2B_336 = 0XB22A
BLAKE2B_344 = 0XB22B
BLAKE2B_352 = 0XB22C
BLAKE2B_360 = 0XB22D
BLAKE2B_368 = 0XB22E
BLAKE2B_376 = 0XB22F
BLAKE2B_384 = 0XB230
BLAKE2B_392 = 0XB231
BLAKE2B_400 = 0XB232
BLAKE2B_408 = 0XB233
BLAKE2B_416 = 0XB234
BLAKE2B_424 = 0XB235
BLAKE2B_432 = 0XB236
BLAKE2B_440 = 0XB237
BLAKE2B_448 = 0XB238
BLAKE2B_456 = 0XB239
BLAKE2B_464 = 0XB23A
BLAKE2B_472 = 0XB23B
BLAKE2B_480 = 0XB23C
BLAKE2B_488 = 0XB23D
BLAKE2B_496 = 0XB23E
BLAKE2B_504 = 0XB23F
BLAKE2B_512 = 0XB240
BLAKE2S_8 = 0XB241
BLAKE2S_16 = 0XB242
BLAKE2S_24 = 0XB243
BLAKE2S_32 = 0XB244
BLAKE2S_40 = 0XB245
BLAKE2S_48 = 0XB246
BLAKE2S_56 = 0XB247
BLAKE2S_64 = 0XB248
BLAKE2S_72 = 0XB249
BLAKE2S_80 = 0XB24A
BLAKE2S_88 = 0XB24B
BLAKE2S_96 = 0XB24C
BLAKE2S_104 = 0XB24D
BLAKE2S_112 = 0XB24E
BLAKE2S_120 = 0XB24F
BLAKE2S_128 = 0XB250
BLAKE2S_136 = 0XB251
BLAKE2S_144 = 0XB252
BLAKE2S_152 = 0XB253
BLAKE2S_160 = 0XB254
BLAKE2S_168 = 0XB255
BLAKE2S_176 = 0XB256
BLAKE2S_184 = 0XB257
BLAKE2S_192 = 0XB258
BLAKE2S_200 = 0XB259
BLAKE2S_208 = 0XB25A
BLAKE2S_216 = 0XB25B
BLAKE2S_224 = 0XB25C
BLAKE2S_232 = 0XB25D
BLAKE2S_240 = 0XB25E
BLAKE2S_248 = 0XB25F
BLAKE2S_256 = 0XB260

NAMES = {
    'identity':      IDENTITY,
    'md4':           MD4,
    'md5':           MD5,
    'sha1':          SHA1,
    'sha2-256':      SHA2_256,
    'sha2-512':      SHA2_512,
    'dbl-sha2-256':  DBL_SHA2_256,
    'sha3-224':      SHA3_224,
    'sha3-256':      SHA3_256,
    'sha3-384':      SHA3_384,
    'sha3-512':      SHA3_512,
    'shake-128':     SHAKE_128,
    'shake-256':     SHAKE_256,
    'keccak-224':    KECCAK_224,
    'keccak-256':    KECCAK_256,
    'keccak-384':    KECCAK_384,
    'keccak-512':    KECCAK_512,
    'murmur3-128':   MURMUR3_128,
    'murmur3-32':    MURMUR3_32,
    'blake2b-8':     BLAKE2B_8,
    'blake2b-16':    BLAKE2B_16,
    'blake2b-24':    BLAKE2B_24,
    'blake2b-32':    BLAKE2B_32,
    'blake2b-40':    BLAKE2B_40,
    'blake2b-48':    BLAKE2B_48,
    'blake2b-56':    BLAKE2B_56,
    'blake2b-64':    BLAKE2B_64,
    'blake2b-72':    BLAKE2B_72,
    'blake2b-80':    BLAKE2B_80,
    'blake2b-88':    BLAKE2B_88,
    'blake2b-96':    BLAKE2B_96,
    'blake2b-104':   BLAKE2B_104,
    'blake2b-112':   BLAKE2B_112,
    'blake2b-120':   BLAKE2B_120,
    'blake2b-128':   BLAKE2B_128,
    'blake2b-136':   BLAKE2B_136,
    'blake2b-144':   BLAKE2B_144,
    'blake2b-152':   BLAKE2B_152,
    'blake2b-160':   BLAKE2B_160,
    'blake2b-168':   BLAKE2B_168,
    'blake2b-176':   BLAKE2B_176,
    'blake2b-184':   BLAKE2B_184,
    'blake2b-192':   BLAKE2B_192,
    'blake2b-200':   BLAKE2B_200,
    'blake2b-208':   BLAKE2B_208,
    'blake2b-216':   BLAKE2B_216,
    'blake2b-224':   BLAKE2B_224,
    'blake2b-232':   BLAKE2B_232,
    'blake2b-240':   BLAKE2B_240,
    'blake2b-248':   BLAKE2B_248,
    'blake2b-256':   BLAKE2B_256,
    'blake2b-264':   BLAKE2B_264,
    'blake2b-272':   BLAKE2B_272,
    'blake2b-280':   BLAKE2B_280,
    'blake2b-288':   BLAKE2B_288,
    'blake2b-296':   BLAKE2B_296,
    'blake2b-304':   BLAKE2B_304,
    'blake2b-312':   BLAKE2B_312,
    'blake2b-320':   BLAKE2B_320,
    'blake2b-328':   BLAKE2B_328,
    'blake2b-336':   BLAKE2B_336,
    'blake2b-344':   BLAKE2B_344,
    'blake2b-352':   BLAKE2B_352,
    'blake2b-360':   BLAKE2B_360,
    'blake2b-368':   BLAKE2B_368,
    'blake2b-376':   BLAKE2B_376,
    'blake2b-384':   BLAKE2B_384,
    'blake2b-392':   BLAKE2B_392,
    'blake2b-400':   BLAKE2B_400,
    'blake2b-408':   BLAKE2B_408,
    'blake2b-416':   BLAKE2B_416,
    'blake2b-424':   BLAKE2B_424,
    'blake2b-432':   BLAKE2B_432,
    'blake2b-440':   BLAKE2B_440,
    'blake2b-448':   BLAKE2B_448,
    'blake2b-456':   BLAKE2B_456,
    'blake2b-464':   BLAKE2B_464,
    'blake2b-472':   BLAKE2B_472,
    'blake2b-480':   BLAKE2B_480,
    'blake2b-488':   BLAKE2B_488,
    'blake2b-496':   BLAKE2B_496,
    'blake2b-504':   BLAKE2B_504,
    'blake2b-512':   BLAKE2B_512,
    'blake2s-8':     BLAKE2S_8,
    'blake2s-16':    BLAKE2S_16,
    'blake2s-24':    BLAKE2S_24,
    'blake2s-32':    BLAKE2S_32,
    'blake2s-40':    BLAKE2S_40,
    'blake2s-48':    BLAKE2S_48,
    'blake2s-56':    BLAKE2S_56,
    'blake2s-64':    BLAKE2S_64,
    'blake2s-72':    BLAKE2S_72,
    'blake2s-80':    BLAKE2S_80,
    'blake2s-88':    BLAKE2S_88,
    'blake2s-96':    BLAKE2S_96,
    'blake2s-104':   BLAKE2S_104,
    'blake2s-112':   BLAKE2S_112,
    'blake2s-120':   BLAKE2S_120,
    'blake2s-128':   BLAKE2S_128,
    'blake2s-136':   BLAKE2S_136,
    'blake2s-144':   BLAKE2S_144,
    'blake2s-152':   BLAKE2S_152,
    'blake2s-160':   BLAKE2S_160,
    'blake2s-168':   BLAKE2S_168,
    'blake2s-176':   BLAKE2S_176,
    'blake2s-184':   BLAKE2S_184,
    'blake2s-192':   BLAKE2S_192,
    'blake2s-200':   BLAKE2S_200,
    'blake2s-208':   BLAKE2S_208,
    'blake2s-216':   BLAKE2S_216,
    'blake2s-224':   BLAKE2S_224,
    'blake2s-232':   BLAKE2S_232,
    'blake2s-240':   BLAKE2S_240,
    'blake2s-248':   BLAKE2S_248,
    'blake2s-256':   BLAKE2S_256,
}

CODES = dict((v, k) for k, v in NAMES.items())

LENGTHS = {
    'sha1': 20,
    'sha2-256': 32,
    'sha2-512': 64,
    'sha3-512': 64,
    'blake2b-512': 64,
    'blake2s-256': 32,
}

FUNCS = {
    SHA1: hashlib.sha1,
    SHA2_256: hashlib.sha256,
    SHA2_512: hashlib.sha512,
}

if sha3:
    FUNCS[SHA3_512] = lambda: hashlib.new('sha3_512')

if pyblake2:
    FUNCS[BLAKE2B_512] = lambda: pyblake2.blake2b()
    FUNCS[BLAKE2S_256] = lambda: pyblake2.blake2s()


def _hashfn(hashfn):
    """Return an initialised hash object, by function, name or integer id

    >>> _hashfn(SHA1) # doctest: +ELLIPSIS
    <sha1 HASH object @ 0x...>

    >>> _hashfn('sha2-256') # doctest: +ELLIPSIS
    <sha2-256 HASH object @ 0x...>
    >>> _hashfn('18') # doctest: +ELLIPSIS
    <sha2-256 HASH object @ 0x...>

    >>> _hashfn('snefru')
    Traceback (most recent call last):
      ...
    ValueError: Unknown hash function "snefru"
    """
    if six.callable(hashfn):
        return hashfn()

    elif isinstance(hashfn, six.integer_types):
        return FUNCS[hashfn]()

    elif isinstance(hashfn, six.string_types):
        if hashfn in NAMES:
            return FUNCS[NAMES[hashfn]]()

        elif hashfn.isdigit():
            return _hashfn(int(hashfn))

    raise ValueError('Unknown hash function "{0}"'.format(hashfn))


def is_app_code(code):
    """Check if the code is an application specific code.

    >>> is_app_code(SHA1)
    False
    >>> is_app_code(0)
    True
    """
    if isinstance(code, six.integer_types):
        return code >= 0 and code < 0x10

    else:
        return False


def is_valid_code(code):
    """Check if the digest algorithm code is valid.

    >>> is_valid_code(SHA1)
    True
    >>> is_valid_code(0)
    True
    """
    if is_app_code(code):
        return True

    elif isinstance(code, six.integer_types):
        return code in CODES

    else:
        return False


def decode(buf):
    r"""Decode a hash from the given Multihash.

    After validating the hash type and length in the two prefix bytes, this
    function removes them and returns the raw hash.

    >>> encoded = b'\x11\x14\xc3\xd4XGWbx`AAh\x01%\xa4o\xef9Nl('
    >>> bytearray(decode(encoded))
    bytearray(b'\xc3\xd4XGWbx`AAh\x01%\xa4o\xef9Nl(')

    >>> decode(encoded) == encoded[2:] == hashlib.sha1(b'thanked').digest()
    True
    """
    if len(buf) < 3:
        raise ValueError('Buffer too short')

    if len(buf) > 129:
        raise ValueError('Buffer too long')

    code, length = struct.unpack('BB', buf[:2])

    if not is_valid_code(code):
        raise ValueError('Invalid code "{0}"'.format(code))

    digest = buf[2:]
    if len(digest) != length:
        raise ValueError('Inconsistent length ({0} != {1})'.format(
            len(digest), length))

    return digest


def encode(content, code):
    """Encode a binary or text string using the digest function corresponding
    to the given code.  Returns the hash of the content, prefixed with the
    code and the length of the digest, according to the Multihash spec.

    >>> encoded = encode('testing', SHA1)
    >>> len(encoded)
    22
    >>> encoded[:2]
    bytearray(b'\\x11\\x07')

    >>> encoded = encode('works with sha3?', SHA3)
    >>> len(encoded)
    66
    >>> encoded[:2]
    bytearray(b'\\x14\\x10')
    """
    if not is_valid_code(code):
        raise TypeError('Unknown code')

    hashfn = _hashfn(code)

    if isinstance(content, six.binary_type):
        hashfn.update(content)
    elif isinstance(content, six.string_types):
        hashfn.update(content.encode('utf-8'))

    digest = hashfn.digest()
    if len(digest) > 127:
        raise ValueError('Multihash does not support digest length > 127')

    output = bytearray([code, len(digest)])
    output.extend(digest)
    return output
