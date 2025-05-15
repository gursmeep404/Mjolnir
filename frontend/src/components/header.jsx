import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import logo from "../../public/logo.svg";
import "../../styles/header.css";
import "../../styles/codex.css"; 

export default function Header() {
  const [visible, setVisible] = useState(true);
  const [prevScrollY, setPrevScrollY] = useState(0);
  const [showCodex, setShowCodex] = useState(false); 
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

  if (location.pathname === "/intro") return null;

  return (
    <>
      <header className={`header ${visible ? "show" : "hide"}`}>
        <div className="logo-box">
          <img src={logo} alt="Mjolnir Scanner Logo" className="logo-img" />
        </div>

        <nav className="nav-box">
          <Link to="/home" className="nav-item">
            Home
          </Link>
          <Link to="/dashboard" className="nav-item">
            Dashboard
          </Link>
          <Link to="/report" className="nav-item">
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
          <button className="gradient-btn" onClick={() => setShowCodex(true)}>
            The Codex
          </button>
        </div>
      </header>

      {/* Modal Popup */}
      {showCodex && (
        <div className="codex-overlay">
          <div className="codex-scroll">
            <button className="codex-close" onClick={() => setShowCodex(false)}>
              ✖
            </button>
            <div className="codex-content">
              <h2>The Codex</h2>
              <p>Hello Wielder!</p>
              <p>
                You now hold <strong>Mjolnir</strong>. I am not just a tool. I
                am a companion in reconaissance.Before you swing me across
                cyberspace, here’s what you need to know.
              </p>
              <h3>Steps to Use Mjolnir</h3>
              <ul>
                <li>
                  <strong>Step 1:</strong> Click on <i>Get Started</i> button on the home page or scroll down to find the <i>Scan</i> button which would allow you to begin the scan.
                </li>
                <li>
                  <strong>Step 2:</strong> Click on Scan and wait till the scanner runs and fetches the results for you. Every IP that you scan will be stored in the database and hence, next time you look up the results for the same IP, scanner will not run and data would directly be fetched from the database. If the IP is being scanned for the first time, please be patient. It might take a few minutes.
                </li>
                <li>
                  <strong>Step 3:</strong>Results would be displayed on the screen once the scanning is complete. If you wish to see all the CVEs then click on <i>Generate Report</i> button present at the end of the page.
                </li>
                <li>
                  <strong>Step 4:</strong> Once the button is clicked wait till the NVD database is queried and results are fetched. You can click on the links int he report to know more about the vulnerabilities.
                </li>
              </ul>

              <p>Clicking on the databse option in the header would display the results of all the IPs scanned so far and stored in the database</p>
              <p>To know more about the scanner visit the about page by clicking the about button on the header or the <i>Learn More</i> button on the home page</p>
              <p>To know more about who built me and to get in touch with my creator click the <i>Contact</i> button on the header and send her an email</p>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
