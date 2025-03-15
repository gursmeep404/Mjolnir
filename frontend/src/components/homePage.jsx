import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import "../../styles/home.css";

export default function Home() {
  const [lightning, setLightning] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setLightning(true);
      setTimeout(() => setLightning(false), 200);
    }, Math.random() * 5000 + 3000); // Randomize lightning strikes
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="home-container">
      {/* Lightning Effect */}
      {lightning && <div className="lightning"></div>}

      {/* Ravens */}
      <motion.img
        src="/ravens.png"
        className="raven raven-left"
        animate={{ x: [0, 50, -50, 0], y: [0, 20, -20, 0] }}
        transition={{ repeat: Infinity, duration: 5 }}
      />
      <motion.img
        src="/ravens.png"
        className="raven raven-right"
        animate={{ x: [0, -50, 50, 0], y: [0, -20, 20, 0] }}
        transition={{ repeat: Infinity, duration: 5 }}
      />

      {/* Mjolnir */}
      <motion.img
        src="/mjolnir.png"
        className="mjolnir"
        initial={{ opacity: 0, y: -50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 1 }}
      />

      {/* Title & Scan Button */}
      <h1 className="title">🛡️ Mjolnir Scanner 🛡️</h1>
      <p className="subtitle">
        "Strike down vulnerabilities like Thor's hammer!"
      </p>

      <Link to="/scan">
        <motion.button
          className="scan-button"
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.9 }}
        >
          Start Scan
        </motion.button>
      </Link>
    </div>
  );
}
