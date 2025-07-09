import React, { useState } from "react";
import axios from "axios";

const URLChecker = () => {
  const [input, setInput] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);

  const checkURL = async () => {
    if (!input.trim()) return setResult("❌ Please enter a URL");

    setLoading(true);
    setResult("");

    try {
      const res = await axios.post("http://localhost:8000/api/verify", {
        qrData: input,
      });
      setResult(res.data.valid ? "✅ Safe URL" : "⚠️ Unsafe or Fake URL");
    } catch (err) {
      setResult("❌ Server Error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 shadow-xl rounded-lg p-8 w-full max-w-lg text-white">
        <h1 className="text-3xl font-bold mb-6 text-center text-blue-400">
          🔍 URL Verification Tool
        </h1>

        <input
          type="text"
          placeholder="Paste URL here..."
          className="w-full px-4 py-3 mb-4 rounded-md bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />

        <button
          onClick={checkURL}
          disabled={loading}
          className={`w-full ${
            loading ? "bg-blue-400 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700"
          } transition duration-200 text-white font-semibold py-2 px-4 rounded-md`}
        >
          {loading ? "Verifying..." : "Verify URL"}
        </button>

        {loading && (
          <div className="mt-4 flex justify-center">
            <div className="w-6 h-6 border-4 border-white border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {result && !loading && (
          <div
            className={`mt-4 text-center text-lg font-semibold ${
              result.includes("✅")
                ? "text-green-400"
                : result.includes("⚠️")
                ? "text-yellow-400"
                : "text-red-400"
            }`}
          >
            {result}
          </div>
        )}
      </div>
    </div>
  );
};

export default URLChecker;



