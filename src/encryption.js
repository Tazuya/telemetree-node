const fs = require("fs");
const path = require("path");
const wasmExecPath = path.join(__dirname, "wasm_exec.js");
require(wasmExecPath);

class EncryptionService {
  constructor(publicKey) {
    this.publicKey = publicKey;
    this.wasmEncrypt = null;
    this.isInitialized = false;
    this.initializeWasm();
  }

  async initializeWasm() {
    if (this.isInitialized) return;

    const go = new Go();
    try {
      const wasmPath = path.join(__dirname, "analytics.wasm");
      const wasmBuffer = fs.readFileSync(wasmPath);
      const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
      go.run(result.instance);

      if (typeof globalThis.encrypt !== "function") {
        throw new Error("WASM encryption function not found");
      }

      this.wasmEncrypt = globalThis.encrypt;
      this.isInitialized = true;
    } catch (err) {
      console.error("Failed to initialize WASM module:", err);
      throw err;
    }
  }

  async encrypt(message) {
    if (!this.isInitialized) {
      await this.initializeWasm();
    }

    try {
      const messageObj =
        typeof message === "string" ? JSON.parse(message) : message;

      if (!messageObj.telegram_id) {
        console.error("Missing telegram_id in message:", messageObj);
        throw new Error("Message must contain telegram_id");
      }

      const messageStr = JSON.stringify(messageObj);
      const result = this.wasmEncrypt(
        this.publicKey,
        messageObj.telegram_id.toString(),
        messageStr
      );

      let encryptedData;
      try {
        encryptedData = JSON.parse(result);
      } catch (parseError) {
        console.error("Failed to parse WASM result:", parseError);
        throw new Error("WASM returned invalid JSON");
      }

      // Detailed validation
      const missingFields = [];
      if (!encryptedData.body) missingFields.push("body");
      if (!encryptedData.key) missingFields.push("key");
      if (!encryptedData.iv) missingFields.push("iv");

      if (missingFields.length > 0) {
        throw new Error(
          `WASM encryption missing fields: ${missingFields.join(", ")}`
        );
      }

      return {
        body: encryptedData.body,
        key: encryptedData.key,
        iv: encryptedData.iv
      };
    } catch (error) {
      console.error("Encryption error:", error);
      throw error;
    }
  }
}

module.exports = EncryptionService;
