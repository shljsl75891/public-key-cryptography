import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {AsymmetricCryptography} from './utils/asymmetric-cryptography.util.js';

const asymmetricCryptography = new AsymmetricCryptography();

const keysPath = join(import.meta.dirname, '../src/keys');
const {publicKey, privateKey} = asymmetricCryptography.generateKeyPair();

writeFileSync(keysPath + '/public_key.pem', publicKey);
writeFileSync(keysPath + '/private_key.pem', privateKey);
