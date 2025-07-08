import QRData from "../models/QRData.js";

export const seedQRData = async (req, res) => {
  try {
    const entries = [
      { data: "https://trusted.com/product/12345", valid: true },
      { data: "https://myshop.com/item/abc", valid: true },
      { data: "http://scam.com/fake", valid: false },
    ];

    await QRData.insertMany(entries);
    res.status(201).json({ message: "Seed data inserted successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
