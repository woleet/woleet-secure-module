import 'mocha';
import * as assert from 'assert';

import { SecureModule, SecureKey } from '../src';
import { publicKeyRegexep } from './util';

const sm = new SecureModule();
let key: Promise<SecureKey>;

before(async () => {
  await sm.init();
  key = sm.createKey();
});

// https://github.com/mochajs/mocha/issues/2975
describe('Key creation', () => {

  it('Function "createKey" should be callable without arguments', async () => {
    assert.doesNotThrow(() => sm.createKey());
    await assert.doesNotReject(() => sm.createKey());
  });

  it('Function "createKey" should reject if called with arguments (1)', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.createKey('toto'), {
      message: 'Function "createKey" does not takes any argument'
     });
  });

  it('Function "createKey" should reject if called with arguments (2)', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.createKey(null), {
       message: 'Function "createKey" does not takes any argument'
       });
  });

  describe('Should return a valid object', () => {

    ['publicKey', 'privateKey', 'entropy'].forEach((prop) => {
      it(`Returned key should have a "${prop}" property`, async () => {
        assert((await key)[prop], `missing "${prop}" property`);
      });
    });

    it(`Attribute "privateKey" should be a Buffer`, async () => {
      assert(Buffer.isBuffer((await key).privateKey), `Attribute "privateKey" should be a Buffer`);
    });

    it(`Attribute "entropy" should be a Buffer`, async () => {
      assert(Buffer.isBuffer((await key).entropy), `Attribute "entropy" should be a Buffer`);
    });

    it(`Attribute "privateKey" should be a valid Buffer`, async () => {
      const privateKey = (await key).privateKey;
      const expectedLen = 32 + 16; // encryption adds 16 bytes on initial buffer
      assert.equal(privateKey.length, 32 + 16, `Attribute "privateKey" should be a ${expectedLen} byte length Buffer`);
    });

    it(`Attribute "entropy" should be a valid Buffer`, async () => {
      const entropy = (await key).entropy;
      const expectedLen = 16 + 16; // encryption adds 16 bytes on initial buffer
      assert.equal(entropy.length, expectedLen, `Attribute "entropy" should be a ${expectedLen} byte length Buffer`);
    });

    it(`Attribute "publicKey" should be a valid bitcoin address`, async () => {
      const publicKey = (await key).publicKey;
      assert(publicKeyRegexep.test(publicKey), `Attribute "publicKey" should match address regexp, got ${publicKey}`);
    });
  });
});
