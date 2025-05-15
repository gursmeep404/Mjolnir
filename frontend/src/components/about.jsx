import "../../styles/about.css";

const About = () => {
  return (
    <div className="about-container">
      <div className="about-card">
        <h1 className="about-title">Mjolnir — The Network Scanner</h1>
        <p className="about-subtitle">
          Understand your machine’s defenses without touching the command line.
        </p>

        <section className="about-section">
          <h2> What is Mjolnir?</h2>
          <p>
            Mjolnir is a web-based network scanner that transforms packet
            analysis into an interactive experience. Developed using React for
            the frontend and Flask for the backend, it uses scapy to scan your system or network — letting users explore the world of
            IPs, packets, and ports in real time.
          </p>
        </section>

        <section className="about-section">
          <h2> Core Features</h2>
          <ul>
            <li> ICMP response analysis & firewall detection</li>
            <li> TCP/UDP scanning to detect open and filtered ports</li>
            <li> Passive OS fingerprinting using TTL</li>
            <li>Packet capturing for deeper inspection</li>
            <li> Vulnerability mapping using NVD database</li>
          </ul>
        </section>

        <section className="about-section">
          <h2>Tech Stack</h2>
          <p>
            React + Vite on the frontend. Flask and Scapy on the backend. Data
            is handled via SQLite, and vulnerability reports are fetched using
            the NVD API.
          </p>
        </section>

        <section className="about-section">
          <h2>Limitations</h2>
          <p>
            Passive OS fingerprinting doesn't provide version-specific output,
            which can cause the CVE report to include older vulnerabilities.
            While not exact, it offers a useful overview of potential
            weaknesses.
          </p>
          <p>
            Some systems may not return results if they have strict firewall
            rules or have disabled network scanning — a common limitation seen
            in tools like Nmap as well.
          </p>
        </section>

        <section className="about-section">
          <h2>Why Mjolnir?</h2>
          <p>
            Mjolnir was built to make network behavior more accessible. Instead
            of abstract theory, it offers direct interaction with packets and
            protocols. I built it to help users intuitively understand what happens behind
            an IP address. It’s both a tool and a teaching companion.
          </p>
        </section>
      </div>
    </div>
  );
};

export default About;
