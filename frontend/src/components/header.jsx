import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import logo from "../../public/logo.svg";
import "../../styles/header.css";

export default function Header() {
  const [visible, setVisible] = useState(true);
  const [prevScrollY, setPrevScrollY] = useState(0);
  const location = useLocation();

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      setVisible(currentScrollY < prevScrollY || currentScrollY < 10);
      setPrevScrollY(currentScrollY);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [prevScrollY]);

  if (location.pathname === "/intro") return null; // Hide header on intro page

  return (
    <header className={`header ${visible ? "show" : "hide"}`}>
      {/* Logo Box */}
      <div className="logo-box">
        <img src={logo} alt="Mjolnir Scanner Logo" className="logo-img" />
      </div>

      {/* Navigation Box */}
      <nav className="nav-box">
        <Link to="/home" className="nav-item">
          Home
        </Link>
        <Link to="/dashboard" className="nav-item">
          Dashboard
        </Link>
        <Link to="/Report" className="nav-item">
          Report
        </Link>
        <Link to="/about" className="nav-item">
          About
        </Link>
        <Link to="/contact" className="nav-item">
          Contact
        </Link>
      </nav>

      <div className="button-box">
        <button className="gradient-btn">The Codex</button>
      </div>
    </header>
  );
}
