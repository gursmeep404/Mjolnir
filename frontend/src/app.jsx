import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Intro from "./components/intro";
import Home from "./components/homePage";
import Header from "./components/header";
import Dashboard from "./components/dashboard";
import React from "react";


const scanData = {
  host_id: 1,
  tcp_open: [135, 445],
  tcp_closed: Array.from({ length: 50 }, (_, i) => i + 1), // Simulating closed ports
  tcp_filtered: [137],
};

function App() {
  return (
    <Router>
      <Header />
      <Routes>
        <Route path="/" element={<Intro />} />
        <Route path="/home" element={<Home />} />
        {/* <Route path="/about" element={<About />} />
        <Route path="/contact" element={<Contact />} /> */}
        <Route path="/intro" element={<Intro />} />
        <Route path="/scan_results" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
