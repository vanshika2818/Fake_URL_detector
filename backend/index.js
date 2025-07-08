import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("🎉 QR Code Validator Backend Running");
});

// 🧠 Smart QR verify route
app.post("/api/verify", async (req, res) => {
  const { qrData } = req.body;

  try {
    const url = new URL(qrData);
    const hostname = url.hostname;

    // Suspicious indicators
    const badKeywords = ["free", "win", "gift", "verify", "login", "claim"];
    const riskyExtensions = [".xyz", ".click", ".info"];
    const shortenedDomains = ["bit.ly", "tinyurl.com", "rb.gy"];

    const isHttps = qrData.startsWith("https://");
    const containsBadWord = badKeywords.some(word => qrData.toLowerCase().includes(word));
    const isShortened = shortenedDomains.includes(hostname);
    const hasRiskyExtension = riskyExtensions.some(ext => hostname.endsWith(ext));

    const isFake = !isHttps || containsBadWord || isShortened || hasRiskyExtension;

    res.json({ valid: !isFake });
  } catch (err) {
    // Invalid or malformed QR data
    res.json({ valid: false });
  }
});

const PORT = 8000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
