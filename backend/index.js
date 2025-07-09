import express from "express";
import cors from "cors";
import axios from "axios";

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = "d26e99ae686910e1a684d02092dee5f066edaa7f3e12ec23e065bbbc73b68e98"; // 🔐 paste your key here

// Health check
app.get("/", (req, res) => {
  res.send("✅ QR URL Detector Backend is Running");
});

app.post("/api/verify", async (req, res) => {
  const { qrData } = req.body;

  try {
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      new URLSearchParams({ url: qrData }),
      {
        headers: {
          "x-apikey": API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }
    );

    const scanId = response.data.data.id;

    // GET the analysis report
    const report = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${scanId}`,
      { headers: { "x-apikey": API_KEY } }
    );

    const stats = report.data.data.attributes.stats;
    const malicious = stats.malicious;

    res.json({
      valid: malicious === 0,
      detail: stats
    });

  } catch (error) {
    console.error("❌ VirusTotal error", error.response?.data || error.message);
    res.status(500).json({ error: "Failed to verify URL." });
  }
});

const PORT = 8000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
