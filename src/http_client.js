const axios = require("axios");

class HttpClient {
  constructor(settings) {
    this.settings = settings;
    this.url = settings.config.host;
    this.apiKey = settings.apiKey;
    this.projectId = settings.projectId;
  }

  async post(data) {
    try {
      // Ensure we're sending a proper JSON object
      if (!data.body || !data.key || !data.iv) {
        throw new Error("Missing required encryption fields");
      }

      const payload = {
        body: String(data.body),
        key: String(data.key),
        iv: String(data.iv)
      };

      // Validate minimum lengths
      if (payload.key.length < 10 || payload.iv.length < 10) {
        throw new Error("Key and IV must be at least 10 characters long");
      }

      const response = await axios.post(this.url, payload, {
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": this.apiKey,
          "X-Project-Id": this.projectId
        }
      });

      console.log("Event Tracking Response:", {
        status: response.status,
        statusText: response.statusText,
        data: response.data,
        headers: response.headers,
        requestTime: new Date().toISOString()
      });

      return {
        success: true,
        status: response.status,
        statusText: response.statusText,
        data: response.data,
        headers: response.headers,
        requestTime: new Date().toISOString()
      };
    } catch (error) {
      const errorResponse = {
        success: false,
        status: error.response?.status,
        statusText: error.response?.statusText,
        error: error.message,
        data: error.response?.data,
        requestTime: new Date().toISOString()
      };
      console.error("Error posting data:", errorResponse);
      return errorResponse;
    }
  }
}

module.exports = HttpClient;
