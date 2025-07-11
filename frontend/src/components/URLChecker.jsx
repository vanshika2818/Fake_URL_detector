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
        url: input,
      });
      setResult(res.data.result);
    } catch (err) {
      console.error(err);
      setResult("❌ Server Error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white flex flex-col items-center justify-center px-4">
      <h1 className="text-4xl font-bold mb-6 text-blue-400 glow">🔍 Fake URL Detector</h1>

      <div className="w-full max-w-md bg-gray-800 rounded-2xl shadow-xl p-6 space-y-4">
        <input
          type="text"
          placeholder="Paste a suspicious URL..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="w-full px-4 py-2 text-lg rounded-xl bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
        />

        <button
          onClick={checkURL}
          disabled={loading}
          className={`w-full py-2 rounded-xl text-lg font-semibold transition ${
            loading
              ? "bg-blue-900 cursor-not-allowed"
              : "bg-blue-500 hover:bg-blue-600"
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center space-x-2">
              <span className="loader border-white"></span>
              <span>Checking...</span>
            </span>
          ) : (
            "Check URL"
          )}
        </button>

        {result && (
          <div
            className={`text-center text-2xl font-bold py-2 rounded-xl mt-4 ${
              result.includes("Safe")
                ? "text-green-400 bg-green-800/40 shadow-green-500"
                : "text-red-400 bg-red-800/40 shadow-red-500"
            }`}
          >
            {result}
          </div>
        )}
      </div>

      <style>
        {`
          .loader {
            border: 3px solid transparent;
            border-top: 3px solid white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 0.8s linear infinite;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          .glow {
            text-shadow: 0 0 10px #3b82f6, 0 0 20px #3b82f6, 0 0 40px #3b82f6;
          }
        `}
      </style>
    </div>
  );
};

export default URLChecker;
