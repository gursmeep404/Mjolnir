import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import "../../styles/home.css";

export default function Home() {
  const [lightning, setLightning] = useState(false);
  const [scanActive, setScanActive] = useState(false);

  const handleScanClick = () => {
    setLightning(true);
    setScanActive(true);
    setTimeout(() => {
      setLightning(false);
      setScanActive(false);
    }, 800);
  };

  return (
    <div className="home-container">
      {/* Lightning Effect */}
      {lightning && <div className="lightning"></div>}

      {/* Ravens */}
      <motion.img
        src="../../public/animal.png"
        className="raven raven-left"
        animate={{ x: [0, 60, -60, 0], y: [0, 25, -25, 0] }}
        transition={{ repeat: Infinity, duration: 6 }}
      />
      <motion.img
        src="../../public/nature.png"
        className="raven raven-right"
        animate={{ x: [0, -60, 60, 0], y: [0, -25, 25, 0] }}
        transition={{ repeat: Infinity, duration: 6 }}
      />

      {/* Mjolnir */}
      <motion.img
        src="/mjolnir.png"
        className="mjolnir"
        animate={scanActive ? { rotate: [0, -10, 10, 0], y: [0, -20, 0] } : {}}
        transition={{ duration: 0.5 }}
      />

      {/* Title & Scan Button */}
      <h1 className="title">⚡ Mjolnir Scanner ⚡</h1>
      <p className="subtitle">
        "Strike down vulnerabilities like Thor's hammer!"
      </p>

      <motion.button
        className="scan-button"
        onClick={handleScanClick}
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.9 }}
      >
        Start Scan
      </motion.button>
    </div>
  );
}
