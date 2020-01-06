import 'mocha';
import * as assert from 'assert';

import { SecureModule } from '../src';
import { validPhrase } from './util';

const sm = new SecureModule;

before(async () => {
  await sm.init();
  await sm.createKey();
});

describe('importPhrase', () => {

  it('Function "importPhrase" should reject if called without argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.importPhrase(), {
      message: 'Function "importPhrase" takes 1 mandatory and 1 optional argument'
    });
  });

  it('Function "importPhrase" should be callable with 1 valid arguments', async () => {
    assert.doesNotThrow(() => sm.importPhrase(validPhrase));
    await assert.doesNotReject(() => sm.importPhrase(validPhrase));
  });

  it('Function "importPhrase" should reject with invalid "phrase" argument', async () => {
    await assert.rejects(() => sm.importPhrase('test'), {
      message: 'Argument "phrase" must be a valid phrase'
    });
  });

  it('Function "importPhrase" should reject with invalid "compressed" argument', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.importPhrase('entropy', 'test'), {
      message: 'Argument "compressed" must be a boolean'
    });
  });

  it('Function "importPhrase" should reject with 3 arguments', async () => {
    // @ts-ignore
    await assert.rejects(() => sm.importPhrase('entropy', true, 'test'), {
      message: 'Function "importPhrase" takes 1 mandatory and 1 optional argument'
    });
  });

  it('Function "exportPhrase" should return the imported phrase', async () => {
    const key = await sm.importPhrase(validPhrase);
    const phrase = await sm.exportPhrase(key.entropy, key.entropyIV);
    assert.strictEqual(phrase, validPhrase, 'Function "exportPhrase" did not returned the expected value');
  });
});
