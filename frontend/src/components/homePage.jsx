import { useRef } from "react";
import { Link } from "react-router-dom";
import "../../styles/home.css";

export default function Home() {
  const secondSectionRef = useRef(null);

  const handleScroll = () => {
    secondSectionRef.current.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div className="home-container">

      {/* Hero Section */}
      <section className="hero">
        <div className="hero-text">
          <h1>Welcome to Mjolnir Scanner</h1>
          <p>
            Discover vulnerabilities with the power of Thor’s hammer. Unleash
            the might of scanning with precision and speed.
          </p>
          <div className="buttons">
            <Link to="/learn-more" className="learn-more-btn">
              Learn More →
            </Link>
            <button className="get-started-btn" onClick={handleScroll}>
              Get Started
            </button>
          </div>
        </div>
        {/* <div className="hero-image">
          <img src="/Cyber attack-pana.png" alt="Vector Illustration" />
        </div> */}
      </section>

      {/* Second Section */}
      <section ref={secondSectionRef} className="second-section">
        <h2>Deep Dive into Scanning</h2>
        <p>Explore the features and capabilities of Mjolnir Scanner.</p>
      </section>

      {/* Third Section */}
      <section className="third-section">
        <h2>Advanced Security Insights</h2>
        <p>Gain powerful insights into cybersecurity threats.</p>
      </section>
    </div>
  );
}
