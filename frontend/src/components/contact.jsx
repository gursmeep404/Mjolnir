import "../../styles/contact.css";

export default function ContactPage() {
  return (
    <div className="contact-container">
      <div className="contact-card">
        <div className="profile-pic">
          <img src="/me1.png" alt="Gursmeep" />
        </div>
        <h1 className="alias">Gursmeep Kaur</h1>
        <p className="role">Hey! Got ideas? Got bugs? Got coffee? Let’s talk.</p>

        <div className="contact-info">
          <p>
            <span className="label">GitHub:</span>{" "}
            <a
              href="https://github.com/16aurora"
              target="_blank"
              rel="noopener noreferrer"
            >
              github.com/16aurora
            </a>
          </p>
          <p>
            <span className="label">Email:</span>{" "}
            <a href="mailto:youremail@example.com">gursmeep5813@gmail.com</a>
          </p>
        </div>
      </div>
    </div>
  );
}