import 'mocha';
import * as assert from 'assert';

import { SecureModule } from '../src';

describe('Module instanciation', () => {

  it('Class "SecureModule" should be instanciable', () => {
    let sm;
    assert.equal(typeof SecureModule, 'function');
    assert.doesNotThrow(() => sm = new SecureModule);
    assert(sm.__proto__);
  });

  ['createKey', 'exportPhrase', 'sign'].forEach((prop) => {
    it(`SecureModule instance should have a "${prop}" function as property`, () => {
      const sm = new SecureModule();
      assert(sm[prop], `missing "${prop}" property`);
      assert.equal(typeof sm[prop], 'function', `The "${prop}" property must be a function`);
    });
  });

});
