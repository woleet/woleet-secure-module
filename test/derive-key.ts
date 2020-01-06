import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import { SecureKey, SecureModule } from '../src';
import { validPhrase } from './util';

const sm = new SecureModule;
let key, keyUncompressed: SecureKey;
const defaultPath = 'm/44\'/0\'/0\'';

before(async () => {
  await sm.init();
  key = await sm.importPhrase(validPhrase);
  keyUncompressed = await sm.importPhrase(validPhrase, false);
});

describe('deriveKey', () => {

  it('Function "deriveKey" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.deriveKey(), {
      message: 'Function "deriveKey" takes 3 mandatory and 1 optional argument'
    });
  });

  it('Function "deriveKey" should reject with 1st invalid argument', async () => {
    await assert.rejects(() => sm.deriveKey(crypto.randomBytes(1), key.entropyIV, defaultPath), {
      message: 'Argument "entropy" must be a 32 bytes buffer'
    });
  });

  it('Function "deriveKey" should reject with 2nd invalid argument', async () => {
    await assert.rejects(() => sm.deriveKey(key.entropy, crypto.randomBytes(1), defaultPath), {
      message: 'Argument "iv" must be a 16 bytes buffer'
    });
  });

  it('Function "deriveKey" should reject with 3rd invalid argument', async () => {
    await assert.rejects(() => sm.deriveKey(key.entropy, key.entropyIV, null), {
      message: 'Argument "path" must be a non empty string'
    });
  });

  it('Function "deriveKey" should reject with invalid entropy', async () => {
    const invalidEntropy = Buffer.from(key.entropy);
    crypto.randomBytes(5).copy(invalidEntropy);
    await assert.rejects(() => sm.deriveKey(invalidEntropy, key.entropyIV, defaultPath), {
      message: 'Failed to decrypt entropy'
    });
  });

  [true, false].forEach((compressed) => {
    it('Function "deriveKey" with default path should produce same key than "importPhrase"', async () => {
      const derivedKey = await sm.deriveKey(key.entropy, key.entropyIV, defaultPath, compressed);
      const keyEntropy = await sm.decrypt(key.entropy, key.entropyIV);
      const derivedKeyEntropy = await sm.decrypt(derivedKey.entropy, derivedKey.entropyIV);
      assert.deepStrictEqual(derivedKeyEntropy, keyEntropy);
      const keyPrivateKey = await sm.decrypt(key.privateKey, key.privateKeyIV);
      const derivedKeyPrivateKey = await sm.decrypt(derivedKey.privateKey, derivedKey.privateKeyIV);
      assert.deepStrictEqual(derivedKeyPrivateKey, keyPrivateKey);
    });
  });
});
