require('dotenv').config();
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');

const secretKey = process.env.SECRET_KEY;

const encrypt = (payload) => {
  // encrypt the payload and return token
  const token = jwt.sign(payload, secretKey, {expiresIn: '1h'});

  const encryptedToken = CryptoJS.AES.encrypt(token, secretKey).toString();
  return encryptedToken;
}

const decrypt = (token) => {
  // return decoded payload
  try{
    const bytes = CryptoJS.AES.decrypt(token, secretKey);
    const decryptedToken = bytes.toString(CryptoJS.enc.Utf8);
    const decoded = jwt.verify(decryptedToken, secretKey);
    return decoded;
  } catch (error) {
    console.error("Invalid token or decryption failed");
    return null;
  }
}

module.exports = {
  encrypt,
  decrypt
}
