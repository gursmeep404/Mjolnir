import { useState, useRef } from "react";
import { Link } from "react-router-dom";
import { useNavigate } from "react-router-dom";
import "../../styles/home.css";

export default function Home() {

  const navigate = useNavigate();

  const secondSectionRef = useRef(null);
  const thirdSectionRef = useRef(null);

  const [isModalOpen, setIsModalOpen] = useState(false); // State to control the modal visibility
  const [ipAddress, setIpAddress] = useState(""); // State to hold the IP entered

  const handleScrollToSecond = () => {
    secondSectionRef.current.scrollIntoView({ behavior: "smooth" });
  };

  const openModal = () => {
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
  };

  const handleIpChange = (event) => {
    setIpAddress(event.target.value);
  };

  const handleScan = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ip: ipAddress }),
      });

      const result = await response.json();
      console.log("Scan result:", result);

      if (response.ok) {
        if (result.status === "scanning") {
          // If the scan is in progress, navigate to the dashboard
          // Without `host_id`, but the data will update as the scan completes.
          navigate(`/dashboard?ip=${ipAddress}`);
        } else {
          // If host_id exists immediately, navigate with the host_id
          navigate(`/dashboard/${result.host_id}?ip=${ipAddress}`);
        }
      } else {
        alert("Scan failed.");
      }
    } catch (error) {
      console.error("Error initiating scan:", error);
      alert("An error occurred while scanning.");
    }
  };
  
  
  
  

  return (
    <div className="home-container">
      {/* Hero Section */}
      <section className="hero">
        <div className="hero-text">
          <h1>THE WEB IS A BATTLEFIELD, ARM YOURSELF</h1>
          <p>
            Map your attack surface, probe for known CVEs, and eliminate blind
            spots in your security posture. With real-time reporting and
            actionable recommendations, Mjolnir helps you harden your defenses
            before adversaries strike.
          </p>
          <div className="buttons">
            <Link to="/learn-more" className="learn-more-btn">
              Learn More →
            </Link>
            <button className="get-started-btn" onClick={handleScrollToSecond}>
              Get Started
            </button>
          </div>
        </div>
        <div className="hero-image">
          <img src="data-analytics.png" alt="Vector Illustration" />
        </div>
      </section>

      {/* Second Section */}
      <section ref={secondSectionRef} className="second-section">
        <h2>Scan for Security Risks</h2>
        <div className="scan-cards">
          <div className="scan-card">
            <img src="/net.png" alt="Network Scan Icon" className="scan-icon" />
            <h3>Network Scan</h3>
            <p>
              Perform a comprehensive security assessment of a specific IP
              address or an entire subnet. Identify open ports, running
              services, and potential misconfigurations that could expose your
              network to attacks.
            </p>
            <button className="scan-btn" onClick={openModal}>
              Scan
            </button>
          </div>
          <div className="scan-card">
            <img src="/web.png" alt="Network Scan Icon" className="scan-icon" />
            <h3>Web Application Scan</h3>
            <p>
              Examine a web application for security vulnerabilities such as SQL
              injection, cross-site scripting (XSS), and misconfigured security
              headers. Detect weaknesses that could allow unauthorized access or
              data breaches.
            </p>
            <button className="scan-btn">Scan</button>
          </div>
        </div>
      </section>

      {/* IP Address Modal */}
      {isModalOpen && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Enter IP Address for Network Scan</h2>
            <input
              type="text"
              value={ipAddress}
              onChange={handleIpChange}
              placeholder="Enter IP Address or Network"
            />
            <p className="modal-note">
              <strong>Note:</strong> To scan a single host, simply input the IP
              address. For scanning a network, provide the subnet mask like:
              <br />
              <code>192.168.1.0/24</code>
            </p>
            <div className="modal-buttons">
              <button onClick={handleScan}>Scan</button>
              <button onClick={closeModal}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Third Section */}
      <section ref={thirdSectionRef} className="third-section">
        {/* Caution Message */}
        <div className="caution-box">
          <h2>⚠️ Ethical Hacking Disclaimer</h2>
          <p>
            This tool is designed to identify vulnerabilities and is to be used
            for security analysis and penetration testing. Unauthorized scanning
            of networks or websites without consent is illegal.
          </p>
          <p>
            Always ensure you have explicit permission before running any scans.
            Misuse could lead to severe legal consequences.
          </p>
        </div>

        <div className="ascii-art">
          <pre>
            {`
      .-"      "-.
     /            \\
    |              |
    |,  .-.  .-.  ,|
    | )(_o/  \\o_)( |
    |/     /\\     \\|
    (_     ^^     _)
     \\__|IIIIII|__/
      | \\IIIIII/ |
      \\          /
       \`--------\`
      `}
          </pre>
          <p className="hacker-quote">
            By the beard of Odin, I shall smite thee!
          </p>
        </div>

        {/* Footer */}
        <footer className="footer">
          <p>© 2024 Mjolnir | Version 1.0.0 | All rights reserved</p>
          <p>
            Developed by <span>Gursmeep Kaur</span>
          </p>
        </footer>
      </section>
    </div>
  );
}
