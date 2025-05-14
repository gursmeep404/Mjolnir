import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import axios from "axios";

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
    <div className="report-container">
      <h2>Vulnerability Report for {state?.ip}</h2>
      {loading ? (
        <p>Loading...</p>
      ) : cveData.length > 0 ? (
        <ul>
          {cveData.map((cve, index) => (
            <li key={index}>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                {cve.id}
              </a>{" "}
              - {cve.summary}
            </li>
          ))}
        </ul>
      ) : (
        <p>No known vulnerabilities found.</p>
      )}
    </div>
  );
};

export default Report;
