import * as crypto from 'crypto';
import * as message from 'bitcoinjs-message';
import * as read from 'read';
import { HDPrivateKey, KeyRing, Mnemonic } from 'bcoin';
import { promisify } from 'util';

type Base58Address = string;

export interface SecureKey {
  entropyIV: Buffer;
  entropy: Buffer;
  privateKeyIV: Buffer;
  privateKey: Buffer;
  publicKey: Base58Address;
  compressed: boolean;
}

export class SecureModule {

  private secret: Buffer = null;

  private static _randomBytes(n: number): Buffer {
    return crypto.randomBytes(n);
  }

  private _encrypt(data: Buffer, iv: Buffer): Buffer {
    const cipher = crypto.createCipheriv('aes-256-cbc', this.secret, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  private _decrypt(data: Buffer, iv: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.secret, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  private _derive(entropy: Buffer, path: string, compressed: boolean = true): SecureKey {

    // Get mnemonic from entropy;
    const mnemonic = Mnemonic.fromEntropy(entropy);

    // Create HD master key from mnemonic
    const hdMasterKey = HDPrivateKey.fromMnemonic(mnemonic);

    // Derive HD master key to HD private key
    const hdPrivateKey = hdMasterKey.derivePath(path);

    // Create a key ring from the HD private key
    const ring = KeyRing.fromPrivate(hdPrivateKey.privateKey, compressed);
    const publicKey = ring.getAddress();
    const privateKey = ring.getPrivateKey();

    // Encrypt the entropy
    const entropyIV = SecureModule._randomBytes(16);
    const encryptedEntropy = this._encrypt(mnemonic.getEntropy(), entropyIV);

    // Encrypt the HD private key
    const privateKeyIV = SecureModule._randomBytes(16);
    const encryptedPrivateKey = this._encrypt(privateKey, privateKeyIV);

    // Return the key
    return {
      entropyIV: entropyIV,
      entropy: encryptedEntropy,
      privateKeyIV: privateKeyIV,
      privateKey: encryptedPrivateKey,
      publicKey: publicKey.toBase58(),
      compressed
    };
  }

  private initialized(): boolean {
    return !!this.secret;
  }

  public async init(variable = 'ENCRYPTION_SECRET'): Promise<void> {
    if (arguments.length > 1) {
      throw new Error('Function "init" may take only one (optional) argument');
    }

    if (typeof variable !== 'string' || !variable) {
      throw new Error('Argument "variable" must be a non empty string');
    }

    let secret = process.env[variable] || '';

    if (!secret) {
      console.warn(`No ${variable} environment set, please enter encryption secret:`);
      const options = { prompt: '>', silent: true };
      const _read = promisify(read);
      while (!secret) {
        secret = await _read(options);
        if (!secret) {
          console.warn('Encryption secret must not be empty, please type it:');
        }
      }
    }

    this.secret = crypto.createHash('sha256')
      .update(secret, 'utf8')
      .digest();
  }

  public async encrypt(data: Buffer): Promise<{ data: Buffer, iv: Buffer }> {
    const iv = SecureModule._randomBytes(16);
    return {
      data: this._encrypt(data, iv),
      iv
    };
  }

  public async decrypt(data: Buffer, iv: Buffer): Promise<Buffer> {
    return this._decrypt(data, iv);
  }

  public async createKey(): Promise<SecureKey> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 0) {
      throw new Error('Function "createKey" does not take any argument');
    }

    // Get random mnemonic
    const mnemonic = new Mnemonic();

    // Return a key created from random mnemonic using the default derivation path
    return this._derive(mnemonic.getEntropy(), 'm/44\'/0\'/0\'');
  }

  public async deriveKey(entropy: Buffer, iv: Buffer, path: string, compressed: boolean = true): Promise<SecureKey> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 3 && arguments.length !== 4) {
      throw new Error('Function "deriveKey" takes 3 mandatory and 1 optional argument');
    }

    if (!(Buffer.isBuffer(entropy) && entropy.length === 32)) {
      throw new Error('Argument "entropy" must be a 32 bytes buffer');
    }

    if (!(Buffer.isBuffer(iv) && iv.length === 16)) {
      throw new Error('Argument "iv" must be a 16 bytes buffer');
    }

    if (typeof path !== 'string' || !path) {
      throw new Error('Argument "path" must be a non empty string');
    }

    if (typeof compressed !== 'boolean') {
      throw new Error('Argument "compressed" must be a boolean');
    }

    // Decrypt entropy
    let decryptedEntropy = null;
    try {
      decryptedEntropy = this._decrypt(entropy, iv);
    } catch (err) {
      throw new Error('Failed to decrypt entropy');
    }

    // Return a key created from entropy using the requested derivation path
    return this._derive(decryptedEntropy, path, compressed);
  }

  public async importPhrase(phrase: string, compressed: boolean = true): Promise<SecureKey> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 1 && arguments.length !== 2) {
      throw new Error('Function "importPhrase" takes 1 mandatory and 1 optional argument');
    }

    if (typeof phrase !== 'string' || !phrase) {
      throw new Error('Argument "phrase" must be a non empty string');
    }

    if (typeof compressed !== 'boolean') {
      throw new Error('Argument "compressed" must be a boolean');
    }

    // Convert phrase to mnemonic
    let mnemonic;
    try {
      mnemonic = Mnemonic.fromPhrase(phrase);
    } catch (err) {
      throw new Error('Argument "phrase" must be a valid phrase');
    }

    // Return a key created from mnemonic using the default derivation path
    return this._derive(mnemonic.getEntropy(), 'm/44\'/0\'/0\'', compressed);
  }

  public async exportPhrase(entropy: Buffer, iv: Buffer): Promise<string> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 2) {
      throw new Error('Function "exportPhrase" takes 2 mandatory arguments');
    }

    if (!(Buffer.isBuffer(entropy) && entropy.length === 32)) {
      throw new Error('Argument "entropy" must be a 32 bytes buffer');
    }

    if (!(Buffer.isBuffer(iv) && iv.length === 16)) {
      throw new Error('Argument "iv" must be a 16 bytes buffer');
    }

    // Decrypt entropy
    let decryptedEntropy = null;
    try {
      decryptedEntropy = this._decrypt(entropy, iv);
    } catch (err) {
      throw new Error('Failed to decrypt entropy');
    }

    // Get mnemonic from entropy
    const mnemonic = Mnemonic.fromEntropy(decryptedEntropy);

    // Return mnemonic phrase
    return mnemonic.getPhrase();
  }

  public async sign(key: Buffer, msg: string, iv: Buffer, compressed: boolean = true): Promise<string> {

    if (!this.initialized()) {
      throw new Error('Secure module is not initialized');
    }

    if (arguments.length !== 3 && arguments.length !== 4) {
      throw new Error('Function "sign" takes 3 mandatory and 1 optional argument');
    }

    if (!(Buffer.isBuffer(key) && key.length === 48)) {
      throw new Error('Argument "key" must be a 48 bytes buffer');
    }

    if (typeof msg !== 'string' || !msg) {
      throw new Error('Argument "message" must be a non empty string');
    }

    if (!(Buffer.isBuffer(iv) && iv.length === 16)) {
      throw new Error('Argument "iv" must be a 16 bytes buffer');
    }

    if (typeof compressed !== 'boolean') {
      throw new Error('Argument "compressed" must be a boolean');
    }

    // Decrypt key
    let decryptedKey = null;
    try {
      decryptedKey = this._decrypt(key, iv);
    } catch (err) {
      throw new Error('Failed to decrypt key');
    }

    // Sign and return the signature
    return message.sign(msg, decryptedKey, compressed).toString('base64');
  }
}
