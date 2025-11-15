
import test from "node:test"
import assert from "node:assert"
import * as jose from 'jose'

test('generateKeyPair', async (t) => {
  // const k = await jose.generateKeyPair('ES256')
  // const pub = await jose.exportJWK(k.publicKey)
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'zQwCN0Q1A2OF-vzRFYMDTThEjkSl3o6vSonhDQwHHz4',
    y: 'ahiGLX7rLYv4DIlKk017zC-zqgzexrxoVuQvaJuObzA',
  }
  console.log(JSON.stringify(jwk))
  const thumbprint = await jose.calculateJwkThumbprint(jwk)
  assert.strictEqual(thumbprint, "sF8ijcZ3yIRTT6M9vtM_jMouZZKTtlkCM5BwbK75mck")
});