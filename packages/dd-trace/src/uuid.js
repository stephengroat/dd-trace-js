'use strict'

const crypto = require('crypto')

const { randomFillSync } = crypto

// Implements an RFC 4122 version 4 random UUID.
// To improve performance, random data is generated in batches
// large enough to cover kBatchSize UUID's at a time. The uuidData
// and uuid buffers are reused. Each call to randomUUID() consumes
// 16 bytes from the buffer.

const kHexDigits = [
  48, 49, 50, 51, 52, 53, 54, 55,
  56, 57, 97, 98, 99, 100, 101, 102
]

const kBatchSize = 128
let uuidData
let uuid
let uuidBatch = 0

// This is a non-cryptographically secure replacement for the native version
// of the `secureBuffer` function used in Node.js core. This means `randomUUID`
// should not be used where cryptographically secure uuids are important.
//
// Node.js core uses a native version which uses `OPENSSL_secure_malloc`
// rather than `randomFillSync`.
function secureBuffer (size) {
  const buf = Buffer.alloc(size)
  return randomFillSync(buf)
}

function getBufferedUUID () {
  if (uuidData === undefined) {
    uuidData = secureBuffer(16 * kBatchSize)
    if (uuidData === undefined) {
      throw new Error('Out of memory')
    }
  }

  if (uuidBatch === 0) randomFillSync(uuidData)
  uuidBatch = (uuidBatch + 1) % kBatchSize
  return uuidData.slice(uuidBatch * 16, (uuidBatch * 16) + 16)
}

function randomUUID () {
  if (uuid === undefined) {
    uuid = Buffer.alloc(36, '-')
    uuid[14] = 52 // '4', identifies the UUID version
  }

  const uuidBuf = getBufferedUUID()

  // Variant byte: 10xxxxxx (variant 1)
  uuidBuf[8] = (uuidBuf[8] & 0x3f) | 0x80

  // This function is structured the way it is for performance.
  // The uuid buffer stores the serialization of the random
  // bytes from uuidData.
  // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  let n = 0
  uuid[0] = kHexDigits[uuidBuf[n] >> 4]
  uuid[1] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[2] = kHexDigits[uuidBuf[n] >> 4]
  uuid[3] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[4] = kHexDigits[uuidBuf[n] >> 4]
  uuid[5] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[6] = kHexDigits[uuidBuf[n] >> 4]
  uuid[7] = kHexDigits[uuidBuf[n++] & 0xf]
  // -
  uuid[9] = kHexDigits[uuidBuf[n] >> 4]
  uuid[10] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[11] = kHexDigits[uuidBuf[n] >> 4]
  uuid[12] = kHexDigits[uuidBuf[n++] & 0xf]
  // -
  // 4, uuid[14] is set already...
  uuid[15] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[16] = kHexDigits[uuidBuf[n] >> 4]
  uuid[17] = kHexDigits[uuidBuf[n++] & 0xf]
  // -
  uuid[19] = kHexDigits[uuidBuf[n] >> 4]
  uuid[20] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[21] = kHexDigits[uuidBuf[n] >> 4]
  uuid[22] = kHexDigits[uuidBuf[n++] & 0xf]
  // -
  uuid[24] = kHexDigits[uuidBuf[n] >> 4]
  uuid[25] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[26] = kHexDigits[uuidBuf[n] >> 4]
  uuid[27] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[28] = kHexDigits[uuidBuf[n] >> 4]
  uuid[29] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[30] = kHexDigits[uuidBuf[n] >> 4]
  uuid[31] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[32] = kHexDigits[uuidBuf[n] >> 4]
  uuid[33] = kHexDigits[uuidBuf[n++] & 0xf]
  uuid[34] = kHexDigits[uuidBuf[n] >> 4]
  uuid[35] = kHexDigits[uuidBuf[n] & 0xf]

  return uuid.latin1Slice(0, 36)
}

module.exports = typeof crypto.randomUUID === 'function'
  ? crypto.randomUUID
  : randomUUID
