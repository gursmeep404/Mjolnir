import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Intro from "./components/intro";
import Home from "./components/homePage";
import Header from "./components/header";
import Dashboard from "./components/dashboard";

function App() {
  return (
    <Router>
      <Header />
      <Routes>
        <Route path="/" element={<Intro />} />
        <Route path="/home" element={<Home />} />
        <Route path="/dashboard/:hostId" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
