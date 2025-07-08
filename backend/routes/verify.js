import express from "express";
import QRData from "../models/QRData.js";

const router = express.Router();

router.post("/verify", async (req, res) => {
  const { qrData } = req.body;

  if (!qrData) return res.status(400).json({ valid: false, message: "No QR data provided" });

  try {
    const record = await QRData.findOne({ data: qrData });

    if (record && record.valid) {
      res.json({ valid: true });
    } else {
      res.json({ valid: false });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ valid: false, error: "Server error" });
  }
});

export default router;

