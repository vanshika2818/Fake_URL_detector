import mongoose from "mongoose";

const qrCodeSchema = new mongoose.Schema({
  data: String,
  valid: Boolean
});

export default mongoose.model("QRCode", qrCodeSchema);
