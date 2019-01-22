import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import * as message from 'bitcoinjs-message';

import { SecureModule, SecureKey } from '../src';
import { validPhrase } from './util';

const sm = new SecureModule;
let encryptedKey: SecureKey;
const hashToSign = crypto.createHash('sha256').digest('hex');

before(async () => {
  await sm.init();
  encryptedKey = await sm.importPhrase(validPhrase);
});

// https://github.com/mochajs/mocha/issues/2975
describe('signature', () => {

  it('Function "sign" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign(), { message: 'Function "sign" takes exactly two arguments' });
  });

  it('Function "sign" should be callable with two valid arguments', async () => {
    assert.doesNotThrow(() => sm.sign(encryptedKey.privateKey, hashToSign));
    await assert.doesNotReject(() => sm.sign(encryptedKey.privateKey, hashToSign));
  });

  it('Function "sign" should reject with one invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign('test'), { message: 'Function "sign" takes exactly two arguments' });
  });

  it('Function "sign" should reject with one invalid argument (1)', async () => {
    const invalid = crypto.randomBytes(32 + 16);
    await assert.rejects(() => sm.sign(invalid, hashToSign), { message: 'Failed to decrypt key' });
  });

  it('Function "sign" should reject with one invalid argument (2)', async () => {
    const invalid = Buffer.concat([encryptedKey.privateKey, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.sign(invalid, hashToSign), { message: 'Argument "key" must be a 38 bytes length buffer' });
  });

  it('Function "sign" should reject with one invalid argument (3)', async () => {
    // @ts-ignore
    // tslint:disable-next-line:max-line-length
    await assert.rejects(() => sm.sign(encryptedKey.privateKey, Buffer.from(hashToSign)), { message: 'Argument "message" must be a string' });
  });

  it('Function "sign" should produce valid signature', async () => {
    const sig = await sm.sign(encryptedKey.privateKey, hashToSign);
    assert(message.verify(hashToSign, encryptedKey.publicKey, sig));
    const expect = 'INadOqMkvrdq9spX1Mp5anK5+OtRED3OWGbhUfXW6igNO6fn1ONsKOPbW+IatF0WExtxAyh4N3L4JVi6gZeYgTg=';
    assert.equal(expect, sig, 'Signature not as expected');
  });

});
