import {generateKeyPairSync, privateDecrypt, publicEncrypt} from 'node:crypto';
import {PASSPHRASE} from '../config.js';

export class AsymmetricCryptography {
  private _privateKey: string | null;
  private _publicKey: string | null;
  private static _instance: AsymmetricCryptography;

  private constructor() {
    this._privateKey = null;
    this._publicKey = null;
  }

  static getInstance(): AsymmetricCryptography {
    if (!this._instance) {
      this._instance = new AsymmetricCryptography();
    }
    return this._instance;
  }

  /** This method generates the public and private key pairs */
  generateKeyPair() {
    const {publicKey, privateKey} = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: PASSPHRASE,
      },
    });
    this._publicKey = publicKey;
    this._privateKey = privateKey;
  }

  /**
   * This method takes the UTF-8 encoded message and returns encrypted message buffer using public key if generated
   * @param message {string} UTF-8 Encoded Message
   * @returns {Buffer | null} The encrypted buffer of message if public key exists
   */
  encryptWithPublicKey(message: string): Buffer | null {
    const bufferMsg = Buffer.from(message, 'utf8');
    if (this._publicKey) {
      return publicEncrypt(this._publicKey, bufferMsg);
    }
    return null;
  }

  /**
   * This method takes the UTF-8 encoded encrypted message with public key
   * and returns decrypted message buffer using private key if generated
   * @param message {Buffer} Encrypted Message Buffer with Public Key
   * @returns {string | null} The decrypted UTF-8 encoded message if corresponding private key exists
   */
  decryptWithPrivateKey(buffer: Buffer): string | null {
    if (this._privateKey) {
      return privateDecrypt(
        {key: this._privateKey, passphrase: PASSPHRASE},
        buffer,
      ).toString();
    }
    return null;
  }

  signWithPrivateKey() {}

  verifySignatureWithPublicKey() {}
}
