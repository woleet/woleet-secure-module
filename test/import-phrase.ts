import 'mocha';
import * as assert from 'assert';
import * as crypto from 'crypto';

import { SecureModule, SecureKey } from '../src';
import { validPhrase } from './util';

const sm = new SecureModule;

before(async () => {
  await sm.init();
  await sm.createKey();
});

// https://github.com/mochajs/mocha/issues/2975
describe('Phrase import', () => {

  it('Function "importPhrase" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.importPhrase(), { message: 'Function "importPhrase" takes only one argument' });
  });

  it('Function "importPhrase" should be callable with one valid arguments', async () => {
    assert.doesNotThrow(() => sm.importPhrase(validPhrase));
    await assert.doesNotReject(() => sm.importPhrase(validPhrase));
  });

  it('Function "importPhrase" should reject with one invalid argument', async () => {
    await assert.rejects(() => sm.importPhrase('test'), { message: 'First argument must be a valid phrase' });
  });

  it('Function "importPhrase" should reject with two arguments', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.importPhrase('entropy', 'test'), { message: 'Function "importPhrase" takes only one argument' });
  });

  it('Function "exportPhrase" should return the imported phrase', async () => {
    const key = await sm.importPhrase(validPhrase);
    const phrase = await sm.exportPhrase(key.entropy);
    assert.equal(phrase, validPhrase, 'Function "exportPhrase" did not returned the expected value');
  });

});
