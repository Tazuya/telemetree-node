const NodeRSA = require("node-rsa");
const crypto = require("crypto");

class EncryptionService {
  constructor(publicKey) {
    console.log("Received public key:", publicKey);
    this.publicKey = new NodeRSA({ environment: "node" });
    const formattedKey = publicKey.includes("-----BEGIN RSA PUBLIC KEY-----")
      ? publicKey
      : `-----BEGIN RSA PUBLIC KEY-----\n${publicKey}\n-----END RSA PUBLIC KEY-----`;
    console.log("Formatted key:", formattedKey);
    this.publicKey.importKey(formattedKey, "pkcs1-public-pem");
  }

  rsaEncrypt(data) {
    try {
      const hexStr = Buffer.isBuffer(data) ? data.toString("hex") : data;
      return this.publicKey.encrypt(Buffer.from(hexStr), "buffer");
    } catch (error) {
      console.error("RSA encryption error:", error);
      throw error;
    }
  }

  generateAesKeyAndIv() {
    const key = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    return [key, iv];
  }

  addPKCS7Padding(data) {
    const blockSize = 16;
    const padding = blockSize - (data.length % blockSize);
    const paddingBuffer = Buffer.alloc(padding, padding);
    return Buffer.concat([data, paddingBuffer]);
  }

  encryptWithAes(key, iv, message) {
    const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
    cipher.setAutoPadding(false);

    const messageBuffer = Buffer.from(message, "utf8");
    const paddedMessage = this.addPKCS7Padding(messageBuffer);

    const encrypted = Buffer.concat([
      cipher.update(paddedMessage),
      cipher.final()
    ]);

    return encrypted;
  }

  encrypt(message) {
    try {
      const [aesKey, iv] = this.generateAesKeyAndIv();
      console.log("Generated AES Key length:", aesKey.length);
      console.log("Generated IV length:", iv.length);

      const encryptedMessage = this.encryptWithAes(aesKey, iv, message);
      console.log("Encrypted message length:", encryptedMessage.length);

      const encryptedKey = this.rsaEncrypt(aesKey);
      const encryptedIv = this.rsaEncrypt(iv);

      console.log("Encrypted key length:", encryptedKey.length);
      console.log("Encrypted IV length:", encryptedIv.length);

      const result = {
        body: encryptedMessage,
        key: encryptedKey,
        iv: encryptedIv
      };

      console.log("Final payload structure:", {
        body_length: encryptedMessage.length,
        key_length: encryptedKey.length,
        iv_length: encryptedIv.length
      });

      return result;
    } catch (error) {
      console.error("Encryption error:", error);
      throw error;
    }
  }
}

module.exports = EncryptionService;
