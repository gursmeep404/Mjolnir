import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Intro from "./components/intro";
import Home from "./components/homePage";
import Header from "./components/header";

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
      </Routes>
    </Router>
  );
}

export default App;
