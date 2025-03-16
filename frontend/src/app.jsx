import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Intro from "./components/intro";
import Home from "./components/homePage";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Intro />} />
        <Route path="/home" element={<Home />} />
      </Routes>
    </Router>
  );
}

export default App;
