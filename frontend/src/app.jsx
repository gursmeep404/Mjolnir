import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import React from "react";
import Intro from "./components/intro";
import Home from "./components/homePage";
import Header from "./components/header";
import Results from "./components/dashboard";

function App() {
  return (
    <Router>
      <Header />
      <Routes>
        <Route path="/" element={<Intro />} />
        <Route path="/home" element={<Home />} />
        <Route path="/dashboard" element={<Results />} />
        <Route path="/intro" element={<Intro />} />
      </Routes>
    </Router>
  );
}

export default App;
