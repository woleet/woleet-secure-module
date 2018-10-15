import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import { SecureModule, SecureKey } from '../src';

const sm = new SecureModule;
let encryptedKey: SecureKey;
const hashToSign = crypto.createHash('sha256').digest('hex')

before(async () => {
  await sm.init();
  encryptedKey = await sm.createKey();
});

// https://github.com/mochajs/mocha/issues/2975
describe('init', () => {

  it('should reject valid sign call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.sign(encryptedKey.privateKey, hashToSign));
  });

  it('should reject valid createKey call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.createKey());
  });

  it('should reject valid exportPhrase call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.exportPhrase(encryptedKey.entropy));
  });

});
