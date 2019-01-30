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
    await assert.rejects(() => sm.sign(key.privateKey, hashToSign, key.privateKeyIV), {
      message: 'Secure module is not initialized'
    });
  });

  it('Should reject valid "createKey" call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.createKey(), {
      message: 'Secure module is not initialized'
    });
  });

  it('Should reject valid "exportPhrase" call if not initialized', async () => {
    const sm = new SecureModule;
    await assert.rejects(() => sm.exportPhrase(key.entropy, key.entropyIV), {
      message: 'Secure module is not initialized'
    });
  });

  it('Should reject "init" call more than one argument', async () => {
    const sm = new SecureModule;
    // @ts-ignore
    await assert.rejects(() => sm.init(key.privateKey, hashToSign, key.privateKeyIV), {
      message: 'Function "init" may take only one (optional) argument'
    });
  });

  it('Should reject "init" call if the first argument is not a string', async () => {
    const sm = new SecureModule;
    // @ts-ignore
    await assert.rejects(() => sm.init(784489), {
      message: 'First argument must be a string'
    });
  });

});
