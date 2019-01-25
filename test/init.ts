import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import { SecureModule, SecureKey } from '../src';

let key: SecureKey;
const hashToSign = crypto.createHash('sha256').digest('hex');

before(async () => {
  const sm = new SecureModule;
  await sm.init();
  key = await sm.createKey();
});

// https://github.com/mochajs/mocha/issues/2975
describe('Module initialization', () => {

  it('Should reject valid "sign" call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.sign(key.privateKey, hashToSign, key.privateKeyIV));
  });

  it('Should reject valid "createKey" call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.createKey());
  });

  it('Should reject valid "exportPhrase" call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.exportPhrase(key.entropy, key.entropyIV));
  });

});
