import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import * as message from 'bitcoinjs-message';

import { SecureModule, SecureKey } from '../src';
import { validPhrase } from './util';

const sm = new SecureModule;
let key: SecureKey;
const hashToSign = crypto.createHash('sha256').digest('hex');

before(async () => {
  await sm.init();
  key = await sm.importPhrase(validPhrase);
});

// https://github.com/mochajs/mocha/issues/2975
describe('signature', () => {

  it('Function "sign" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign(), {
      message: 'Function "sign" takes three arguments, and may take an fourth otional one'
    });
  });

  it('Function "sign" should be callable with three valid arguments', async () => {
    assert.doesNotThrow(() => sm.sign(key.privateKey, hashToSign, key.privateKeyIV));
    await assert.doesNotReject(() => sm.sign(key.privateKey, hashToSign, key.privateKeyIV));
  });

  it('Function "sign" should reject with one invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign('test'), {
      message: 'Function "sign" takes three arguments, and may take an fourth otional one'
    });
  });

  it('Function "sign" should reject with one invalid argument (1)', async () => {
    const invalid = crypto.randomBytes(32 + 16);
    await assert.rejects(() => sm.sign(invalid, hashToSign, key.privateKeyIV), {
      message: 'Failed to decrypt key'
    });
  });

  it('Function "sign" should reject with one invalid argument (2)', async () => {
    const invalid = Buffer.concat([key.privateKey, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.sign(invalid, hashToSign, key.privateKeyIV), {
      message: 'Argument "key" must be a 38 bytes length buffer'
    });
  });

  it('Function "sign" should reject with second invalid argument (3)', async () => {
    // @ts-ignore
    // tslint:disable-next-line:max-line-length
    await assert.rejects(() => sm.sign(key.privateKey, Buffer.from(hashToSign), 'test'), {
      message: 'Argument "message" must be a string'
    });
  });

  it('Function "sign" should reject with third invalid argument (3)', async () => {
    // @ts-ignore
    // tslint:disable-next-line:max-line-length
    await assert.rejects(() => sm.sign(key.privateKey, hashToSign, null), {
      message: 'Argument "iv" must be a 16 bytes buffer'
    });
  });

  it('Function "sign" should produce valid signature', async () => {
    const sig = await sm.sign(key.privateKey, hashToSign, key.privateKeyIV);
    assert(message.verify(hashToSign, key.publicKey, sig));
    const expect = 'INadOqMkvrdq9spX1Mp5anK5+OtRED3OWGbhUfXW6igNO6fn1ONsKOPbW+IatF0WExtxAyh4N3L4JVi6gZeYgTg=';
    assert.equal(expect, sig, 'Signature not as expected');
  });

});
