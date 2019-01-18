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
    await assert.rejects(() => sm.exportPhrase(), { message: 'ExportPhrase takes only one argument'});
  });

  it('Function "exportPhrase" should be callable with one valid arguments', async () => {
    assert.doesNotThrow(() => sm.exportPhrase(encryptedKey.entropy));
    await assert.doesNotReject(() => sm.exportPhrase(encryptedKey.entropy));
  });

  it('Function "exportPhrase" should reject with one invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase('test'), { message: 'First argument must be a 32 bytes length buffer'});
  });

  it('Function "exportPhrase" should reject with two arguments', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.exportPhrase(encryptedKey.entropy, 'test'), { message: 'ExportPhrase takes only one argument'});
  });

  it('Function "exportPhrase" should reject with one invalid arguments (1)', async () => {
    const invalid = Buffer.from(encryptedKey.entropy);
    crypto.randomBytes(5).copy(invalid);
    await assert.rejects(() => sm.exportPhrase(invalid), { message: 'Failed to decrypt entropy'});
  });

  it('Function "exportPhrase" should reject with one invalid arguments (2)', async () => {
    const invalid = Buffer.concat([encryptedKey.entropy, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.exportPhrase(invalid), { message: 'First argument must be a 32 bytes length buffer'});
  });
});
