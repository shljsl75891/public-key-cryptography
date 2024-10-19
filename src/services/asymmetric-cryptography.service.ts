import {
  generateKeyPairSync,
  privateDecrypt,
  privateEncrypt,
  createHash,
  publicDecrypt,
  publicEncrypt,
} from 'node:crypto';
import {PASSPHRASE} from '../config.js';
import {ENCODING, HASHING_ALGORITHM} from '../enum.js';
import {AnyObject, TDataPacket} from '../types.js';

export class AsymmetricCryptographyService {
  private _privateKey: string | null;
  private _publicKey: string | null;
  private static _instance: AsymmetricCryptographyService;

  private constructor() {
    this._privateKey = null;
    this._publicKey = null;
  }

  static getInstance(): AsymmetricCryptographyService {
    if (!this._instance) {
      this._instance = new AsymmetricCryptographyService();
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

  /**
   * This method takes the data and sents the signed SHA-256 hexadecimal hash of data with private key
   * @param data {AnyObject} This represents any data to be signed
   * @returns The hashing algorithm and signed hash using private key
   */
  signWithPrivateKey(
    data: AnyObject,
  ): Omit<TDataPacket, 'originalData'> | null {
    const algorithm = HASHING_ALGORITHM.SHA256;
    const hashedData = this._getHexHash(algorithm, data);

    if (this._privateKey) {
      const signedHash = privateEncrypt(
        {key: this._privateKey, passphrase: PASSPHRASE},
        Buffer.from(hashedData),
      );

      return {algorithm, signedHash};
    }
    return null;
  }

  /**
   * This method checks the data integrity and verify signature using public key
   * @param signedData The hashing algorithm, originalData and signedHash using private key
   * @returns {Boolean} - Whether the data is changed or not while transportation and
   * is it signed by original corresponding private key to the public key being used or not
   */
  verifySignatureWithPublicKey(signedData: TDataPacket): Boolean {
    const {algorithm, originalData, signedHash} = signedData;
    const hashedData = this._getHexHash(algorithm, originalData);

    if (this._publicKey) {
      const decryptedHash = publicDecrypt(this._publicKey, signedHash);
      return decryptedHash.toString() === hashedData;
    }

    return false;
  }

  private _getHexHash(algo: HASHING_ALGORITHM, data: AnyObject): string {
    return createHash(algo).update(JSON.stringify(data)).digest(ENCODING.HEX);
  }
}
