import * as assert from 'assert';
import * as crypto from 'crypto';
import * as message from 'bitcoinjs-message';
import { Mnemonic, HDPrivateKey, KeyRing } from 'bcoin';

export interface SecureKey {
  entropy: Buffer;
  privateKey: Buffer;
  publicKey: Base58Address;
}

export class SecureModule {

  private secret: Buffer = null;

  private encrypt(data: Buffer) {
    const cipher = crypto.createCipher('aes-256-cbc', this.secret);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  private decrypt(data: Buffer) {
    const decipher = crypto.createDecipher('aes-256-cbc', this.secret);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  private initialized() {
    return !!this.secret;
  }

  async init() {
    this.secret = crypto.createHash('sha256')
      .update(process.env.ENCRYPTION_SECRET || 'secret', 'utf8')
      .digest();
  }

  async createKey(): Promise<SecureKey> {
    assert(this.initialized(), 'Secure module is not initialized');
    assert.equal(arguments.length, 0, 'Create key does not takes arguments');

    // Get new phrase
    const mnemonic = Mnemonic.fromPhrase('radio burst level stove exclude violin chief destroy relax depend basket shed');

    // Create an HD private key
    const master = HDPrivateKey.fromMnemonic(mnemonic);
    const xkey = master.derivePath('m/44\'/0\'/0\'');

    const ring = KeyRing.fromPrivate(xkey.privateKey, true);

    const publicKey = ring.getAddress();
    const privateKey = ring.getPrivateKey();

    const encryptedEntropy = this.encrypt(mnemonic.getEntropy());
    const encryptedPrivateKey = this.encrypt(privateKey);

    return {
      entropy: encryptedEntropy,
      privateKey: encryptedPrivateKey,
      publicKey: publicKey.toBase58(),
    };
  }

  async exportPhrase(entropy: Buffer): Promise<string> {
    assert(this.initialized(), 'Secure module is not initialized');
    assert.equal(arguments.length, 1, 'exportPhrase takes only one argument');
    assert.equal(entropy.length, 16 + 16, 'first argument must be a 32 bytes length buffer');

    const decrypted = this.decrypt(entropy);

    // Get key mnemonic
    const mnemonic = Mnemonic.fromEntropy(decrypted);

    // Return phrase
    return mnemonic.getPhrase();
  }

  async sign(key: Buffer, msg: string): Promise<Buffer> {
    assert(this.initialized(), 'Secure module is not initialized');
    assert.equal(arguments.length, 2, 'exportPhrase takes two arguments');
    assert(Buffer.isBuffer(key), 'key must be a buffer');
    assert.equal(key.length, 32 + 16, 'key argument must be a 38 bytes length buffer');
    assert.equal(typeof msg, 'string', 'message argument must be a string');

    const decrypted = this.decrypt(key);
    return message.sign(msg, decrypted, true);
  }

}
