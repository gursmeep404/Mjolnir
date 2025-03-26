import React, { useEffect, useState } from "react";
import axios from "axios";
import { Line } from "react-chartjs-2";
import "../../styles/dashboard.css";

const API_BASE = "http://localhost:5000/api";

const Dashboard = () => {
  const [hosts, setHosts] = useState([]);
  const [tcpResults, setTcpResults] = useState([]);
  const [udpResults, setUdpResults] = useState([]);
  const [icmpResults, setIcmpResults] = useState([]);
  const [osResults, setOsResults] = useState([]);
  const [packets, setPackets] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const responses = await Promise.all([
          axios.get(`${API_BASE}/hosts`),
          axios.get(`${API_BASE}/tcp_results`),
          axios.get(`${API_BASE}/udp_results`),
          axios.get(`${API_BASE}/icmp_results`),
          axios.get(`${API_BASE}/os_results`),
          axios.get(`${API_BASE}/packets`),
        ]);

        const [hostsRes, tcpRes, udpRes, icmpRes, osRes, packetsRes] =
          responses.map((res) => res.data);

        console.log("Fetched Data:", {
          hostsRes,
          tcpRes,
          udpRes,
          icmpRes,
          osRes,
          packetsRes,
        });

        setHosts(hostsRes || []);
        setTcpResults(tcpRes || []);
        setUdpResults(udpRes || []);
        setIcmpResults(icmpRes || []);
        setOsResults(osRes || []);
        setPackets(packetsRes || []);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, []);

  return (
    <div className="dashboard">
     

      <div className="grid-container">
        <div className="panel hosts">
          <h2>🖥️ Hosts Detected</h2>
          <p>{hosts.length} Hosts Found</p>
          <ul>
            {hosts.length > 0 ? (
              hosts.map((host, index) => (
                <li key={index}>
                  {host.host || "Unknown IP"} - Last Scanned:{" "}
                  {host.last_scanned || "Unknown Time"}
                </li>
              ))
            ) : (
              <p>No hosts detected</p>
            )}
          </ul>
        </div>

        <div className="panel tcp-results">
          <h2>🌍 TCP Port Scan Results</h2>
          <div className="port-grid">
            {tcpResults.length > 0 ? (
              tcpResults.map((result, index) => {
                const openPorts = JSON.parse(result.tcp_open || "[]");
                const filteredPorts = JSON.parse(result.tcp_filtered || "[]");
                const closedPorts = JSON.parse(result.tcp_closed || "[]");

                return (
                  <div key={index} className="port-box">
                    <h3>Host {result.host_id}</h3>

                    {/* Open Ports Section */}
                    <div className="port-section">
                      <h4 className="open-title">🟢 Open Ports</h4>
                      <div className="port-tiles open">
                        {openPorts.map((port) => (
                          <div
                            key={port}
                            className="tile open"
                            title={`Port ${port} is open.`}
                          >
                            {port}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Filtered Ports Section */}
                    <div className="port-section">
                      <h4 className="filtered-title">🟣 Filtered Ports</h4>
                      <div className="port-tiles filtered">
                        {filteredPorts.map((port) => (
                          <div
                            key={port}
                            className="tile filtered"
                            title={`Port ${port} is filtered.`}
                          >
                            {port}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Closed Ports Summary */}
                    <p className="closed-summary">
                      🔴 {closedPorts.length} ports are closed.
                    </p>
                  </div>
                );
              })
            ) : (
              <p>No TCP results available</p>
            )}
          </div>
        </div>

        <div className="panel chart">
          <h2>🛡️ UDP Scan Results</h2>
          <div className="port-grid">
            {udpResults.length > 0 ? (
              udpResults.map((result, index) => {
                const openPorts = JSON.parse(result.udp_open || "[]");
                const filteredPorts = JSON.parse(result.udp_filtered || "[]");
                const closedPorts = JSON.parse(result.udp_closed || "[]");

                return (
                  <div key={index} className="port-box">
                    <h3>Host {result.host_id}</h3>

                    {/* Open Ports Section */}
                    <div className="port-section">
                      <h4 className="open-title">🟢 Open Ports</h4>
                      <div className="port-tiles open">
                        {openPorts.map((port) => (
                          <div
                            key={port}
                            className="tile open"
                            title={`Port ${port} is open.`}
                          >
                            {port}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Filtered Ports Section */}
                    <div className="port-section">
                      <h4 className="filtered-title">🟣 Filtered Ports</h4>
                      <div className="port-tiles filtered">
                        {filteredPorts.map((port) => (
                          <div
                            key={port}
                            className="tile filtered"
                            title={`Port ${port} is filtered.`}
                          >
                            {port}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Closed Ports Summary */}
                    <p className="closed-summary">
                      🔴 {closedPorts.length} ports are closed.
                    </p>
                  </div>
                );
              })
            ) : (
              <p>No UDP results available</p>
            )}
          </div>
        </div>

        <div className="panel chart">
          <h2>📡 ICMP Responses</h2>
          {icmpResults.length > 0 ? (
            <ul>
              {icmpResults.map((icmp, index) => {
                // Parse the JSON string inside icmp_responses
                let responses = [];
                try {
                  responses = JSON.parse(icmp.icmp_responses);
                } catch (error) {
                  console.error("Error parsing ICMP responses:", error);
                }

                return responses.map((response, i) => (
                  <li key={`${index}-${i}`}>
                    <strong>Host:</strong> {response.host} |
                    <strong> Type:</strong> {response.type} |
                    <strong> Code:</strong> {response.code} |
                    <strong> Description:</strong> {response.description}
                  </li>
                ));
              })}
            </ul>
          ) : (
            <p>No ICMP responses detected</p>
          )}
        </div>

        <div className="panel os">
          <h2>💻 OS Fingerprinting</h2>
          {osResults.length > 0 ? (
            <ul>
              {osResults.map((os, index) => (
                <li key={index}>
                  <strong>OS Guess:</strong> {os.os_guess || "Unknown"} |
                  <strong> Window Size:</strong> {os.window_size || "N/A"} |
                  <strong> TTL:</strong> {os.ttl || "N/A"}
                </li>
              ))}
            </ul>
          ) : (
            <p>No OS data available</p>
          )}
        </div>

        <div className="panel terminal">
          <h2>📡 Packet Capture (Live)</h2>
          <div className="terminal-feed">
            {packets.length > 0 ? (
              packets.slice(0, 10).map((pkt, index) => (
                <p key={index}>
                  <strong>#{pkt.id || index}</strong> |
                  {pkt.packet_summary || "No summary available"} | ⏱{" "}
                  {pkt.timestamp || "Unknown"}
                </p>
              ))
            ) : (
              <p>No packets captured</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
