import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import { SecureModule, SecureKey } from '../src';

const sm = new SecureModule;
let encryptedKey: SecureKey;

before(async () => {
  await sm.init();
  encryptedKey = await sm.createKey();
});

// https://github.com/mochajs/mocha/issues/2975
describe('Phrase export', () => {

  it('Function "exportPhrase" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase(), {
      message: 'ExportPhrase takes exactly two arguments'
    });
  });

  it('Function "exportPhrase" should be callable with two valid arguments', async () => {
    assert.doesNotThrow(() => sm.exportPhrase(encryptedKey.entropy, encryptedKey.entropyIV));
    await assert.doesNotReject(() => sm.exportPhrase(encryptedKey.entropy, encryptedKey.entropyIV));
  });

  it('Function "exportPhrase" should reject with invalid number of argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase('test'), {
      message: 'ExportPhrase takes exactly two arguments'
    });
  });

  it('Function "exportPhrase" should reject with invalid second argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase(encryptedKey.entropy, 'test'), {
      message: 'Argument "iv" must be a 16 bytes buffer'
    });
  });

  it('Function "exportPhrase" should reject with invalid first argument', async () => {
    const invalid = Buffer.from(encryptedKey.entropy);
    crypto.randomBytes(5).copy(invalid);
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase(invalid, encryptedKey.entropyIV), {
      message: 'Failed to decrypt entropy'
    });
  });

  it('Function "exportPhrase" should reject with invalid first arguments (2)', async () => {
    const invalid = Buffer.concat([encryptedKey.entropy, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.exportPhrase(invalid, encryptedKey.entropyIV), {
      message: 'First argument must be a 32 bytes length buffer'
    });
  });
});
