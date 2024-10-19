import {HASHING_ALGORITHM} from './enum.js';

export type AnyObject = Record<string, any>;

export type TDataPacket = {
  algorithm: HASHING_ALGORITHM;
  originalData: AnyObject;
  signedHash: Buffer;
};
