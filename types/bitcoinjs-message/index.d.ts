/// <reference types="node" />

declare module 'bitcoinjs-message' {

  /**
   * A base 64 encoded string
   */
  type Base64String = string;

  /**
   * A base 58 encoded string
   */
  type BitcoinAddress = string;

  export function magicHash(message: string, messagePrefix?: Buffer | string): Buffer;
  export function sign(message: string, privateKey: Buffer, compressed?: boolean, messagePrefix?: Buffer | string): Buffer;
  export function verify(message: string, address: BitcoinAddress, signature: Buffer | Base64String, messagePrefix?: Buffer | string): boolean;

}
