import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import axios from "axios";
import "../../styles/report.css";

const Report = () => {
  const { state } = useLocation();
  const [cveData, setCveData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        console.log("Data sent to backend:", state);

        const response = await axios.post(
          "http://localhost:5000/api/generate_report",
          state
        );
        setCveData(response.data.cves);
      } catch (error) {
        console.error("Error fetching CVE report:", error);
      } finally {
        setLoading(false);
      }
    };

    if (state) fetchReport();
  }, [state]);

  return (
    <div className="report-wrapper">
      <div className="report-card">
        <h2>Vulnerability Report</h2>
        <p>Target IP: {state?.ip}</p>
        {loading ? (
          <p>Loading...</p>
        ) : cveData.length > 0 ? (
          cveData.map((cve, index) => (
            <div key={index} className="cve-entry">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                {cve.id}
              </a>
              <div className="cve-summary">{cve.summary}</div>
            </div>
          ))
        ) : (
          <p>No known vulnerabilities found.</p>
        )}
      </div>
    </div>
  );
};

export default Report;
