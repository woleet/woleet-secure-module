import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import * as message from 'bitcoinjs-message';
import * as base58 from 'bs58';

import { SecureModule, SecureKey } from '../src';

const sm = new SecureModule;
let encryptedKey: SecureKey;
const hashToSign = crypto.createHash('sha256').digest('hex');

before(async () => {

  await sm.init();

  encryptedKey = await sm.createKey();

});

// https://github.com/mochajs/mocha/issues/2975
describe('signature', () => {

  it('sign function should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign());
  });

  it('sign function should be callable with two valid arguments', async () => {
    assert.doesNotThrow(() => sm.sign(encryptedKey.privateKey, hashToSign));
    await assert.doesNotReject(() => sm.sign(encryptedKey.privateKey, hashToSign));
  });

  it('sign function should reject with one invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign('test'));
  });

  it('sign function should reject with one invalid argument (1)', async () => {
    const invalid = crypto.randomBytes(32 + 16);
    await assert.rejects(() => sm.sign(invalid, hashToSign));
  });

  it('sign function should reject with one invalid argument (2)', async () => {
    const invalid = Buffer.concat([encryptedKey.privateKey, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.sign(invalid, hashToSign));
  });

  it('sign function should reject with one invalid argument (3)', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign(encryptedKey.privateKey, Buffer.from(hashToSign)));
  });

  it('sign function should produce valid signature', async () => {
    const sig = await sm.sign(encryptedKey.privateKey, hashToSign);
    assert(message.verify(hashToSign, encryptedKey.publicKey, sig.toString('base64')));
  });

});
