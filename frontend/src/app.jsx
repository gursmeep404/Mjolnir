import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import React, { useEffect, useRef } from "react";
import Intro from "./components/intro";
import Home from "./components/homePage";
import Header from "./components/header";
import Dashboard from "./components/dashboard";

function App() {
  const audioRef = useRef(null);

  useEffect(() => {
    const playAudio = () => {
      if (audioRef.current) {
        audioRef.current.volume = 0.5; 
        audioRef.current.play().catch((error) => {
          console.error("Autoplay failed:", error);
        });
      }
    };

    
    const hasPlayed = sessionStorage.getItem("musicPlayed");

    if (!hasPlayed) {
      playAudio(); 
      sessionStorage.setItem("musicPlayed", "true"); 
    }

    document.addEventListener("click", playAudio, { once: true });

    return () => {
      document.removeEventListener("click", playAudio);
    };
  }, []);

  return (
    <Router>
      <audio ref={audioRef} src="music.mp3" />
      <Header />
      <Routes>
        <Route path="/" element={<Intro />} />
        <Route path="/home" element={<Home />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
