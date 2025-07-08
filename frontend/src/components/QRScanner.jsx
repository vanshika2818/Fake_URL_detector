import React, { useState } from "react";
import axios from "axios";

const QRScanner = () => {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);

  const checkQR = async () => {
    try {
      const res = await axios.post("http://localhost:8000/api/verify", {
        qrData: input
      });
      setResult(res.data.valid ? "✅ Genuine" : "❌ Fake");
    } catch (err) {
      setResult("❌ Error occurred");
    }
  };

  return (
    <div className="p-4">
      <input
        type="text"
        placeholder="Paste QR Code Data Here"
        className="border p-2 w-full"
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />
      <button
        className="mt-2 px-4 py-2 bg-blue-500 text-white rounded"
        onClick={checkQR}
      >
        Check QR
      </button>
      {result && <p className="mt-4 text-xl">{result}</p>}
    </div>
  );
};
export default QRScanner;

