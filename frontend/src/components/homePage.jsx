import { useRef } from "react";
import { Link } from "react-router-dom";
import "../../styles/home.css";

export default function Home() {
  const secondSectionRef = useRef(null);
  const thirdSectionRef = useRef(null);

  const handleScrollToSecond = () => {
    secondSectionRef.current.scrollIntoView({ behavior: "smooth" });
  };

  const handleScrollToThird = () => {
    thirdSectionRef.current.scrollIntoView({ behavior: "smooth" });
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
            <button className="scan-btn">Scan</button>
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

      {/* Third Section */}
      <section ref={thirdSectionRef} className="third-section">
        <h2>Advanced Security Insights</h2>
        <p>Gain powerful insights into cybersecurity threats.</p>
      </section>
    </div>
  );
}
