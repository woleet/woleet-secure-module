import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import { SecureKey, SecureModule } from '../src';

const sm = new SecureModule;
let encryptedKey: SecureKey;

before(async () => {
  await sm.init();
  encryptedKey = await sm.createKey();
});

describe('exportPhrase', () => {

  it('Function "exportPhrase" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase(), {
      message: 'Function "exportPhrase" takes 2 mandatory arguments'
    });
  });

  it('Function "exportPhrase" should be callable with 2 valid arguments', async () => {
    assert.doesNotThrow(() => sm.exportPhrase(encryptedKey.entropy, encryptedKey.entropyIV));
    await assert.doesNotReject(() => sm.exportPhrase(encryptedKey.entropy, encryptedKey.entropyIV));
  });

  it('Function "exportPhrase" should reject with invalid number of argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase('test'), {
      message: 'Function "exportPhrase" takes 2 mandatory arguments'
    });
  });

  it('Function "exportPhrase" should reject with invalid "iv" argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase(encryptedKey.entropy, 'test'), {
      message: 'Argument "iv" must be a 16 bytes buffer'
    });
  });

  it('Function "exportPhrase" should reject with invalid "entropy" argument (1)', async () => {
    const invalid = Buffer.from(encryptedKey.entropy);
    crypto.randomBytes(5).copy(invalid);
    await assert.rejects(() => sm.exportPhrase(invalid, encryptedKey.entropyIV), {
      message: 'Failed to decrypt entropy'
    });
  });

  it('Function "exportPhrase" should reject with invalid "entropy" argument (2)', async () => {
    const invalid = Buffer.concat([encryptedKey.entropy, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.exportPhrase(invalid, encryptedKey.entropyIV), {
      message: 'Argument "entropy" must be a 32 bytes buffer'
    });
  });
});
