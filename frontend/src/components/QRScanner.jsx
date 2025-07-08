import React, { useState } from "react";
import axios from "axios";

const QRScanner = () => {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const checkURL = async () => {
    if (!input.trim()) {
      setResult("❌ Please enter URL.");
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post("http://localhost:8000/api/verify", {
        qrData: input, // backend still expects 'qrData'
      });
      setResult(res.data.valid ? "✅ Genuine URL" : "❌ Fake URL");
    } catch (err) {
      setResult("⚠️ Server error. Try again later.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-black p-4">
      <div className="bg-gray-900 border border-gray-700 text-white rounded-lg shadow-2xl p-8 w-full max-w-md text-center">
        <h1 className="text-3xl font-bold text-cyan-400 mb-6">🕵️‍♀️ Fake URL Detector</h1>

        <input
          type="text"
          placeholder="Paste your URL here..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="w-full px-4 py-3 text-white bg-gray-800 border border-gray-600 rounded-lg mb-4 focus:outline-none focus:ring-2 focus:ring-cyan-400"
        />

        <button
          onClick={checkURL}
          className="bg-cyan-500 hover:bg-cyan-600 text-white font-semibold py-2 px-6 rounded-lg transition duration-300"
        >
          {loading ? "Checking..." : "Verify URL"}
        </button>

        {result && (
          <div
            className={`mt-6 text-lg font-semibold ${
              result.includes("✅")
                ? "text-green-400"
                : result.includes("❌")
                ? "text-red-400"
                : "text-yellow-400"
            }`}
          >
            {result}
          </div>
        )}
      </div>
    </div>
  );
};

export default QRScanner;


