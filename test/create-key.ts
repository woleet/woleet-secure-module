import 'mocha';
import * as assert from 'assert';
import * as base58 from 'bs58';

import { SecureModule, SecureKey } from '../src';
import { publicKeyRegexep } from './util';

const sm = new SecureModule();
let key: Promise<SecureKey>;

before(async () => {
  await sm.init();
  key = sm.createKey();
});

// https://github.com/mochajs/mocha/issues/2975
describe('key creation', () => {

  it('createKey function should be callable without arguments', async () => {
    assert.doesNotThrow(() => sm.createKey());
    await assert.doesNotReject(() => sm.createKey());
  });

  it('createKey function should reject if called with arguments (1)', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.createKey('toto'));
  });

  it('createKey function should reject if called with arguments (2)', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.createKey(null));
  });

  describe('should return a valid object', () => {

    ['publicKey', 'privateKey', 'entropy'].forEach((prop) => {
      it(`Returned key should have a "${prop}" property`, async () => {
        assert((await key)[prop], `missing "${prop}" property`);
      });
    });

    it(`publicKey should be a Buffer`, async () => {
      assert(Buffer.isBuffer((await key).publicKey), `"publicKey" should be a Buffer`);
    });

    it(`privateKey should be a Buffer`, async () => {
      assert(Buffer.isBuffer((await key).privateKey), `"privateKey" should be a Buffer`);
    });

    it(`entropy should be a Buffer`, async () => {
      assert(Buffer.isBuffer((await key).privateKey), `"entropy" should be a Buffer`);
    });

    it(`privateKey should be a valid Buffer`, async () => {
      const privateKey = (await key).privateKey;
      const expectedLen = 32 + 16; // encryption adds 16 bytes on initial buffer
      assert.equal(privateKey.length, 32 + 16, `"privateKey" should be a ${expectedLen} byte length Buffer`);
    });

    it(`entropy should be a valid Buffer`, async () => {
      const entropy = (await key).entropy;
      const expectedLen = 16 + 16; // encryption adds 16 bytes on initial buffer
      assert.equal(entropy.length, expectedLen, `"entropy" should be a ${expectedLen} byte length Buffer`);
    });

    it(`publicKey should be a valid bitcoin address`, async () => {
      const publicKey = (await key).publicKey;
      const address = base58.encode(publicKey);
      const expectedLen = 25; // encryption adds 16 bytes on initial buffer
      assert.equal(publicKey.length, expectedLen, `"publicKey" should be a ${expectedLen} byte length Buffer`);
      assert(publicKeyRegexep.test(address), `"publicKey" should match address regexp, got ${publicKey}`);
    });
  });
});
