import {MESSAGE} from './config.js';
import {AsymmetricCryptography} from './utils/asymmetric-cryptography.util.js';

const asymmetricCryptography = AsymmetricCryptography.getInstance();
asymmetricCryptography.generateKeyPair();

const encryptedBuffer = asymmetricCryptography.encryptWithPublicKey(MESSAGE);

if (encryptedBuffer) {
  const decryptedMsg =
    asymmetricCryptography.decryptWithPrivateKey(encryptedBuffer);

  if (decryptedMsg) {
    console.log('Decrypted Message: ', decryptedMsg);
  }
}
