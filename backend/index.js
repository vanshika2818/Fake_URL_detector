import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Submit a URL for scanning
app.post("/api/verify", async (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ error: "URL is required" });

  try {
    // Step 1: Submit URL to scan
    const scanRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    const scanData = await scanRes.json();
    const scanId = scanData.data.id;

    // Step 2: Poll result endpoint
    const resultURL = `https://www.virustotal.com/api/v3/analyses/${scanId}`;
    let result;
    let tries = 0;

    while (tries < 10) {
      const resultRes = await fetch(resultURL, {
        headers: { "x-apikey": API_KEY },
      });

      const resultData = await resultRes.json();
      const status = resultData.data.attributes.status;

      if (status === "completed") {
        result = resultData;
        break;
      }

      await new Promise((r) => setTimeout(r, 1500));
      tries++;
    }

    if (!result) return res.status(504).json({ error: "Scan timed out" });

    // Step 3: Check malicious status
    const stats = result.data.attributes.stats;
    const maliciousCount = stats.malicious;

    res.json({
      url,
      result: maliciousCount > 0 ? "❌ Malicious" : "✅ Safe",
      maliciousCount,
    });
  } catch (error) {
    console.error("VirusTotal API error:", error);
    res.status(500).json({ error: "Server Error" });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running at http://localhost:${process.env.PORT}`);
});
