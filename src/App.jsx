"use client"

import { useState, useEffect } from "react"
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck, Eye, Globe, Lock, AlertCircle, Info } from "lucide-react"
import "./App.css"

const SUSPICIOUS_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".click",
  ".download",
  ".loan",
  ".racing",
  ".review",
  ".science",
  ".work",
  ".party",
  ".trade",
  ".webcam",
  ".win",
]

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "short.link",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "adf.ly",
  "bl.ink",
  "lnkd.in",
  "tiny.cc",
]

const LEGITIMATE_DOMAINS = [
  "google.com",
  "facebook.com",
  "amazon.com",
  "microsoft.com",
  "apple.com",
  "netflix.com",
  "youtube.com",
  "twitter.com",
  "instagram.com",
  "linkedin.com",
  "github.com",
  "stackoverflow.com",
  "wikipedia.org",
  "reddit.com",
]

function App() {
  const [url, setUrl] = useState("")
  const [analysis, setAnalysis] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const analyzeURL = (inputUrl) => {
    if (!inputUrl.trim()) return null

    try {
      let fullUrl = inputUrl
      if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
        fullUrl = "https://" + inputUrl
      }

      const urlObj = new URL(fullUrl)
      const domain = urlObj.hostname.toLowerCase()
      const tld = domain.substring(domain.lastIndexOf("."))

      let score = 100
      const issues = []

      // Check if it's an IP address
      const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)
      if (isIP) {
        score -= 30
        issues.push("Uses IP address instead of domain name")
      }

      // Check for suspicious TLD
      if (SUSPICIOUS_TLDS.includes(tld)) {
        score -= 25
        issues.push(`Suspicious top-level domain: ${tld}`)
      }

      // Check if it's a URL shortener
      const isShortener = URL_SHORTENERS.some((shortener) => domain.includes(shortener))
      if (isShortener) {
        score -= 20
        issues.push("URL shortener detected - destination unknown")
      }

      // Check for typosquatting
      for (const legitDomain of LEGITIMATE_DOMAINS) {
        if (
          domain !== legitDomain &&
          domain.includes(legitDomain.replace(".com", "")) &&
          domain.length > legitDomain.length
        ) {
          score -= 35
          issues.push(`Possible typosquatting of ${legitDomain}`)
          break
        }
      }

      // Check for excessive subdomains
      const subdomainCount = domain.split(".").length - 2
      const hasSubdomains = subdomainCount > 0
      if (subdomainCount > 2) {
        score -= 15
        issues.push("Excessive subdomains detected")
      }

      // Check URL length
      if (inputUrl.length > 100) {
        score -= 10
        issues.push("Unusually long URL")
      }

      // Check for suspicious characters
      const suspiciousChars = /[а-я]|[α-ω]/.test(domain)
      if (suspiciousChars) {
        score -= 40
        issues.push("Contains suspicious Unicode characters")
      }

      // Check for HTTPS
      const httpsEnabled = urlObj.protocol === "https:"
      if (!httpsEnabled) {
        score -= 15
        issues.push("Not using secure HTTPS protocol")
      }

      // Check for suspicious patterns
      if (domain.includes("secure") || domain.includes("verify") || domain.includes("update")) {
        score -= 20
        issues.push("Contains suspicious keywords often used in phishing")
      }

      // Determine risk level
      let risk
      if (score >= 80) risk = "safe"
      else if (score >= 60) risk = "low"
      else if (score >= 40) risk = "medium"
      else risk = "high"

      return {
        score: Math.max(0, score),
        risk,
        issues,
        details: {
          domain,
          tld,
          isIP,
          isShortener,
          hasSubdomains,
          length: inputUrl.length,
          suspiciousChars,
          httpsEnabled,
        },
      }
    } catch (error) {
      return {
        score: 0,
        risk: "high",
        issues: ["Invalid URL format"],
        details: {
          domain: "Invalid",
          tld: "Invalid",
          isIP: false,
          isShortener: false,
          hasSubdomains: false,
          length: inputUrl.length,
          suspiciousChars: false,
          httpsEnabled: false,
        },
      }
    }
  }

  useEffect(() => {
    if (url.trim()) {
      setIsAnalyzing(true)
      const timeoutId = setTimeout(() => {
        setAnalysis(analyzeURL(url))
        setIsAnalyzing(false)
      }, 300)

      return () => clearTimeout(timeoutId)
    } else {
      setAnalysis(null)
      setIsAnalyzing(false)
    }
  }, [url])

  const getRiskColor = (risk) => {
    switch (risk) {
      case "safe":
        return "safe"
      case "low":
        return "low"
      case "medium":
        return "medium"
      case "high":
        return "high"
      default:
        return "unknown"
    }
  }

  const getRiskIcon = (risk) => {
    const iconProps = { size: 20 }
    switch (risk) {
      case "safe":
        return <ShieldCheck {...iconProps} />
      case "low":
        return <Shield {...iconProps} />
      case "medium":
        return <ShieldAlert {...iconProps} />
      case "high":
        return <AlertTriangle {...iconProps} />
      default:
        return <Shield {...iconProps} />
    }
  }

  return (
    <div className="app">
      <div className="container">
        {/* Header */}
        <div className="header">
          <div className="header-content">
            <div className="header-icon">
              <Shield size={32} />
            </div>
            <h1>URL Security Scanner</h1>
          </div>
          <p className="header-description">Analyze URLs for potential security threats and suspicious patterns</p>
        </div>

        {/* Main Card */}
        <div className="main-card">
          <div className="card-header">
            <Globe size={24} />
            <h2>URL Analysis</h2>
          </div>

          {/* URL Input */}
          <div className="input-section">
            <label htmlFor="url-input">Enter URL to analyze</label>
            <input
              id="url-input"
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="url-input"
            />
          </div>

          {/* Loading State */}
          {isAnalyzing && (
            <div className="loading">
              <div className="spinner"></div>
              <p>Analyzing URL...</p>
            </div>
          )}

          {/* Analysis Results */}
          {analysis && !isAnalyzing && (
            <div className="results">
              {/* Safety Score */}
              <div className="score-card">
                <div className="score-header">
                  <h3>Security Score</h3>
                  <span className="score">{analysis.score}/100</span>
                </div>
                <div className="progress-bar">
                  <div
                    className={`progress-fill ${getRiskColor(analysis.risk)}`}
                    style={{ width: `${analysis.score}%` }}
                  />
                </div>
              </div>

              {/* Risk Level */}
              <div className={`risk-card ${getRiskColor(analysis.risk)}`}>
                <div className="risk-content">
                  <div className="risk-info">
                    {getRiskIcon(analysis.risk)}
                    <div>
                      <h3>Risk Level</h3>
                      <p>{analysis.risk} risk detected</p>
                    </div>
                  </div>
                  <div className="risk-badge">{analysis.risk === "safe" ? "SAFE" : "CAUTION"}</div>
                </div>
              </div>

              {/* Security Issues */}
              {analysis.issues.length > 0 && (
                <div className="issues-card">
                  <div className="issues-header">
                    <AlertCircle size={20} />
                    <h3>Security Issues Found</h3>
                  </div>
                  <ul className="issues-list">
                    {analysis.issues.map((issue, index) => (
                      <li key={index}>
                        <span className="issue-bullet"></span>
                        {issue}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* URL Details */}
              <div className="details-grid">
                {/* Technical Details */}
                <div className="details-card">
                  <div className="details-header">
                    <Eye size={20} />
                    <h3>Technical Details</h3>
                  </div>
                  <div className="details-content">
                    <div className="detail-row">
                      <span>Domain</span>
                      <code>{analysis.details.domain}</code>
                    </div>
                    <div className="detail-row">
                      <span>TLD</span>
                      <code>{analysis.details.tld}</code>
                    </div>
                    <div className="detail-row">
                      <span>Protocol</span>
                      <div className="protocol-info">
                        <Lock size={16} className={analysis.details.httpsEnabled ? "secure" : "insecure"} />
                        <span className={analysis.details.httpsEnabled ? "secure" : "insecure"}>
                          {analysis.details.httpsEnabled ? "HTTPS" : "HTTP"}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Security Metrics */}
                <div className="details-card">
                  <div className="details-header">
                    <Shield size={20} />
                    <h3>Security Metrics</h3>
                  </div>
                  <div className="details-content">
                    <div className="detail-row">
                      <span>URL Length</span>
                      <span>{analysis.details.length} chars</span>
                    </div>
                    <div className="detail-row">
                      <span>IP Address</span>
                      <span className={analysis.details.isIP ? "insecure" : "secure"}>
                        {analysis.details.isIP ? "Yes" : "No"}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span>URL Shortener</span>
                      <span className={analysis.details.isShortener ? "insecure" : "secure"}>
                        {analysis.details.isShortener ? "Detected" : "None"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommendations */}
              <div className="recommendations-card">
                <div className="recommendations-header">
                  <Info size={20} />
                  <h3>Recommendations</h3>
                </div>

                <div className="recommendations-content">
                  {analysis.risk === "safe" && (
                    <p className="recommendation safe">✓ This URL appears to be safe to visit.</p>
                  )}
                  {analysis.risk === "low" && (
                    <p className="recommendation low">⚠ Exercise caution when visiting this URL.</p>
                  )}
                  {analysis.risk === "medium" && (
                    <p className="recommendation medium">
                      ⚠ This URL has suspicious characteristics. Verify before visiting.
                    </p>
                  )}
                  {analysis.risk === "high" && (
                    <p className="recommendation high">🚫 This URL appears highly suspicious. Avoid visiting.</p>
                  )}

                  <div className="tips-grid">
                    <div className="tips-section">
                      <h4>Best Practices</h4>
                      <ul>
                        <li>Verify URLs from unknown sources</li>
                        <li>Look for HTTPS on sensitive sites</li>
                        <li>Check for domain typos</li>
                      </ul>
                    </div>
                    <div className="tips-section">
                      <h4>Warning Signs</h4>
                      <ul>
                        <li>Shortened URLs hiding destinations</li>
                        <li>Suspicious Unicode characters</li>
                        <li>Excessive subdomains</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
