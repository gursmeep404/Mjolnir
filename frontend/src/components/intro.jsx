import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import "../../styles/intro.css";

export default function Intro() {
  const [step, setStep] = useState(0);
  const navigate = useNavigate(); 
  
  useEffect(() => {
    const timers = [
      setTimeout(() => setStep(1), 6000), // Show Norse text after 2s
      setTimeout(() => setStep(2), 12000), // Show "Let the hunt begin" after 4s
      setTimeout(() => navigate("/home"), 16000),
    ];
    return () => timers.forEach(clearTimeout); // Cleanup timers
  }, []);

  return (
    <div className="intro-container">
      <video autoPlay muted loop className="intro-video">
        <source src="bg-video1.mp4" type="video/mp4" />
      </video>

      {step === 0 && (
        <motion.h1
          className="mjolnir-title"
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 1.5 }}
        >
          MJOLNIR
        </motion.h1>
      )}

      {step === 1 && (
        <motion.h2
          className="norse-text"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 1.5 }}
        >
          Aðeins hinir verðugu munu vega kraft Mjǫlnis.
        </motion.h2>
      )}

      {step === 2 && (
        <motion.h3
          className="hunt-text"
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 1.5 }}
        >
          Let the hunt begin ! 
        </motion.h3>
      )}
    </div>
  );
}