import 'mocha';
import * as assert from 'assert';

import { SecureModule } from '../src';

describe('instance', () => {

  it('should be instanciable', () => {
    let sm;
    assert.equal(typeof SecureModule, 'function');
    assert.doesNotThrow(() => sm = new SecureModule);
    assert(sm.__proto__);
  });

  ['createKey', 'exportPhrase', 'sign'].forEach((prop) => {
    it(`should have a "${prop}" property`, () => {
      const sm = new SecureModule();
      assert(sm[prop], `missing "${prop}" property`);
    });
  });

});
