import 'mocha';
import * as assert from 'assert';

import { SecureModule } from '../src';

const sm = new SecureModule;

before(async () => {
  await sm.init();
});

describe('{en|de}crypt', () => {

  it('Function "encrypt" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.encrypt());
  });

  it('Function "encrypt" should reject if called with an invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.encrypt(3));
  });

  it('Function "encrypt" should be callable with 1 valid argument', async () => {
    // @ts-ignore
    await assert.doesNotReject(() => sm.encrypt('test'));
  });

  it('Function "decrypt" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.decrypt());
  });

  it('Function "decrypt" should reject with if called with 1 invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.decrypt(3));
  });

  it('Function "decrypt" should reject with if called with 2 invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.decrypt(3, 3));
  });

  it('Function "decrypt" should be return the same result as passed in the function "encrypt"', async () => {
    const testString = 'test';
    let decryptedString = null;
    let encryptedData;
    let encryptedIV;
    // @ts-ignore
    await assert.doesNotReject(() => sm.encrypt(testString).then((enc) => {
      encryptedData = enc.data;
      encryptedIV = enc.iv;
    }));
    await assert.doesNotReject(() => sm.decrypt(encryptedData, encryptedIV).then((buffer) => {
      decryptedString = buffer.toString('utf8');
    }));
    assert.strictEqual(decryptedString, testString);
  });
});
