import 'mocha';
import * as assert from 'assert';

import { SecureModule } from '../src';

const sm = new SecureModule;

before(async () => {
  await sm.init();
});

// https://github.com/mochajs/mocha/issues/2975
describe('crypt', () => {

  it('Function "encrypt" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.encrypt());
  });

  it('Function "encrypt" should reject if called with an invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.encrypt(3), {
      message: 'The "data" argument must be one of type string, Buffer, TypedArray, or DataView. Received type number'
    });
  });

  it('Function "encrypt" should be callable with a valid argument', async () => {
    // @ts-ignore
    await assert.doesNotReject(() => sm.encrypt('test'));
  });

  it('Function "decrypt" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.decrypt());
  });

  it('Function "decrypt" should reject with if called with one invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.decrypt(3));
  });

  it('Function "decrypt" should reject with if called with two invalid argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.decrypt(3, 3));
  });

  it('Function "decrypt" should be return the same result as passed in the function "encrypt"', async () => {
    const testString = 'test';
    let decryptedString;
    let encryptedData;
    let encryptedIv;
    // @ts-ignore
    await assert.doesNotReject(() => sm.encrypt(testString).then( (enc) => {
      encryptedData = enc.data;
      encryptedIv = enc.iv;
      }));
    await assert.doesNotReject(() => sm.decrypt(encryptedData, encryptedIv).then( (buffer) => {
      decryptedString = buffer.toString('utf8');
    }));
    assert.equal(decryptedString, testString);
  });

});
