import {DATA, MESSAGE} from './config.js';
import {AsymmetricCryptographyService} from './services/asymmetric-cryptography.service.js';

const asymmCryptoService = AsymmetricCryptographyService.getInstance();
asymmCryptoService.generateKeyPair();

// Encryption
const encryptedBuffer = asymmCryptoService.encryptWithPublicKey(MESSAGE);
if (encryptedBuffer) {
  const decryptedMsg =
    asymmCryptoService.decryptWithPrivateKey(encryptedBuffer);

  if (decryptedMsg) {
    console.log('Decrypted Message: ', decryptedMsg);
  }
}

// Data integrity and Digital Signature verification
const signedData = asymmCryptoService.signWithPrivateKey(DATA);
if (signedData) {
  const isVerified = asymmCryptoService.verifySignatureWithPublicKey({
    ...signedData,
    originalData: DATA,
  });

  if (isVerified) {
    console.log('The signature and data both are verified');
  } else {
    console.log('Either data is not correct or signature is wrong');
  }
}
