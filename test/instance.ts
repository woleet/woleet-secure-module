import 'mocha';
import * as assert from 'assert';

import { SecureModule } from '../src';

describe('instance', () => {

  it('Class "SecureModule" should be instantiable', () => {
    let sm = null;
    assert.strictEqual(typeof SecureModule, 'function');
    assert.doesNotThrow(() => sm = new SecureModule);
    assert(sm.__proto__);
  });

  ['createKey', 'exportPhrase', 'sign'].forEach((prop) => {
    it(`SecureModule instance should have a "${prop}" function as property`, () => {
      const sm = new SecureModule();
      assert(sm[prop], `missing "${prop}" property`);
      assert.strictEqual(typeof sm[prop], 'function', `The "${prop}" property must be a function`);
    });
  });
});
