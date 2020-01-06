import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import * as message from 'bitcoinjs-message';

import { SecureKey, SecureModule } from '../src';
import { validPhrase } from './util';

const sm = new SecureModule;
let key, keyUncompressed: SecureKey;
const hashToSign = crypto.createHash('sha256').digest('hex');

before(async () => {
  await sm.init();
  key = await sm.importPhrase(validPhrase);
  keyUncompressed = await sm.importPhrase(validPhrase, false);
});

describe('sign', () => {

  it('Function "sign" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign(), {
      message: 'Function "sign" takes 3 mandatory and 1 optional argument'
    });
  });

  it('Function "sign" should be callable with 3 valid arguments', async () => {
    assert.doesNotThrow(() => sm.sign(key.privateKey, hashToSign, key.privateKeyIV));
    await assert.doesNotReject(() => sm.sign(key.privateKey, hashToSign, key.privateKeyIV));
  });

  it('Function "sign" should reject with 1st invalid argument (1)', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign('test'), {
      message: 'Function "sign" takes 3 mandatory and 1 optional argument'
    });
  });

  it('Function "sign" should reject with 1st invalid argument (2)', async () => {
    const invalid = crypto.randomBytes(32 + 16);
    await assert.rejects(() => sm.sign(invalid, hashToSign, key.privateKeyIV), {
      message: 'Failed to decrypt key'
    });
  });

  it('Function "sign" should reject with 1st invalid argument (3)', async () => {
    const invalid = Buffer.concat([key.privateKey, crypto.randomBytes(2)]);
    await assert.rejects(() => sm.sign(invalid, hashToSign, key.privateKeyIV), {
      message: 'Argument "key" must be a 48 bytes buffer'
    });
  });

  it('Function "sign" should reject with 2nd invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.sign(key.privateKey, Buffer.from(hashToSign), 'test'), {
      message: 'Argument "message" must be a non empty string'
    });
  });

  it('Function "sign" should reject with 3rd invalid argument', async () => {
    await assert.rejects(() => sm.sign(key.privateKey, hashToSign, null), {
      message: 'Argument "iv" must be a 16 bytes buffer'
    });
  });

  it('Function "sign" should produce valid signature', async () => {
    const sig = await sm.sign(key.privateKey, hashToSign, key.privateKeyIV);
    assert(message.verify(hashToSign, key.publicKey, sig));
    const expect = 'INadOqMkvrdq9spX1Mp5anK5+OtRED3OWGbhUfXW6igNO6fn1ONsKOPbW+IatF0WExtxAyh4N3L4JVi6gZeYgTg=';
    assert.strictEqual(expect, sig);
  });

  it('Function "sign" should produce valid signature with uncompressed key', async () => {
    const sig = await sm.sign(keyUncompressed.privateKey, hashToSign, keyUncompressed.privateKeyIV, false);
    assert(message.verify(hashToSign, keyUncompressed.publicKey, sig));
    const expect = 'HNadOqMkvrdq9spX1Mp5anK5+OtRED3OWGbhUfXW6igNO6fn1ONsKOPbW+IatF0WExtxAyh4N3L4JVi6gZeYgTg=';
    assert.strictEqual(expect, sig);
  });
});
