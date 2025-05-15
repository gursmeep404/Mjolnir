import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Intro from "./components/intro";
import Home from "./components/homePage";
import Header from "./components/header";
import Dashboard from "./components/dashboard";
import Report from "./components/report"
import Contact from "./components/contact"
import About from "./components/about"

function App() {
  return (
    <Router>
      <Header />
      <Routes>
        <Route path="/" element={<Intro />} />
        <Route path="/home" element={<Home />} />
        <Route path="/dashboard/:hostId" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/report" element={<Report />} />
        <Route path="/contact" element={<Contact/>}/>
        <Route path="/about" element={<About/>}/>
      </Routes>
    </Router>
  );
}

export default App;
