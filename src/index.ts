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

  // https://en.wikipedia.org/wiki/Initialization_vector
  private iv: Buffer = null;

  private initialized() {
    return !!this.secret;
  }

  private _encrypt(data: Buffer) {
    const cipher = crypto.createCipheriv('aes-256-cbc', this.secret, this.iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  private _decrypt(data: Buffer) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.secret, this.iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  public async init(): Promise<void> {
    this.secret = crypto.createHash('sha256')
      .update(process.env.ENCRYPTION_SECRET || 'secret', 'utf8')
      .digest();

    this.iv = crypto.createHash('sha256')
      .update('W').update('O').update('L')
      .digest()
      .slice(0, 16);
  }

  public async encrypt(data: Buffer): Promise<Buffer> {
    return this._encrypt(data);
  }

  public async decrypt(data: Buffer): Promise<Buffer> {
    return this._decrypt(data);
  }

  public async createKey(): Promise<SecureKey> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 0) {
      throw new Error('Function "createKey" does not takes arguments');
    }

    // Get random phrase
    const mnemonic = new Mnemonic();

    return this.importPhrase(mnemonic.getPhrase());
  }

  public async importPhrase(phrase: string): Promise<SecureKey> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 1) {
      throw new Error('Function "importPhrase" takes only one argument');
    }

    if (typeof phrase !== 'string') {
      throw new Error('First argument must be a string');
    }

    let mnemonic;
    // Get new phrase
    try {
      mnemonic = Mnemonic.fromPhrase(phrase);
    } catch (err) {
      throw new Error('First argument must be a valid phrase');
    }

    // Create an HD private key
    const master = HDPrivateKey.fromMnemonic(mnemonic);
    const xkey = master.derivePath('m/44\'/0\'/0\'');

    const ring = KeyRing.fromPrivate(xkey.privateKey, true);

    const publicKey = ring.getAddress();
    const privateKey = ring.getPrivateKey();

    const encryptedEntropy = this._encrypt(mnemonic.getEntropy());
    const encryptedPrivateKey = this._encrypt(privateKey);

    return {
      entropy: encryptedEntropy,
      privateKey: encryptedPrivateKey,
      publicKey: publicKey.toBase58(),
    };
  }

  public async exportPhrase(entropy: Buffer): Promise<string> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 1) {
      throw new Error('ExportPhrase takes only one argument');
    }

    if (entropy.length !== (16 + 16)) {
      throw new Error('First argument must be a 32 bytes length buffer');
    }

    let decrypted = null;
    try {
      decrypted = this._decrypt(entropy);
    } catch (err) {
      throw new Error('Failed to decrypt entropy');
    }

    // Get key mnemonic
    const mnemonic = Mnemonic.fromEntropy(decrypted);

    // Return phrase
    return mnemonic.getPhrase();
  }

  public async sign(key: Buffer, msg: string): Promise<string> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 2) {
      throw new Error('Function "sign" takes exactly two arguments');
    }

    if (!Buffer.isBuffer(key)) {
      throw new Error('Argument "key"  must be a buffer');
    }

    if (key.length !== (32 + 16)) {
      throw new Error('Argument "key" must be a 38 bytes length buffer');
    }

    if (typeof msg !== 'string') {
      throw new Error('Argument "message" must be a string');
    }

    let decrypted = null;
    try {
      decrypted = this._decrypt(key);
    } catch (err) {
      throw new Error('Failed to decrypt key');
    }

    return message.sign(msg, decrypted, true).toString('base64');
  }

}
