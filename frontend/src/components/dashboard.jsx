import  { useEffect, useState, useMemo, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
// import "react-circular-progressbar/dist/styles.css";

import "../../styles/dashboard.css";

const API_BASE = "http://localhost:5000/api";

const Dashboard = () => {

  const navigate = useNavigate();

  const handleGenerateReport = () => {
    navigate("/report", {
      state: {
        ip,
        tcpResults,
        udpResults,
        osResults,
        firewallResults,
        icmpResults,
      },
    });
  };

  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const ip = queryParams.get("ip");

  const [hosts, setHosts] = useState([]);
  const [tcpResults, setTcpResults] = useState([]);
  const [udpResults, setUdpResults] = useState([]);
  const [icmpResults, setIcmpResults] = useState([]);
  const [osResults, setOsResults] = useState([]);
  const [packets, setPackets] = useState([]);
  const [firewallResults, setFirewallResults] = useState([]);
  const [serviceResults, setServiceResults] = useState([]);
  const logRef = useRef(null);
  const colors = ["#00a8ff", "#ff4d6d", "#9b5de5", "#fcbf49", "#00c897"];
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    let interval;
    const fetchData = async () => {
      const params = { params: { ip } };

      try {
        const endpoints = [
          "hosts",
          "tcp_results",
          "udp_results",
          "icmp_results",
          "os_results",
          "packets",
          "firewall_results",
          "service_results",
        ];

        const responses = await Promise.all(
          endpoints.map((endpoint) =>
            axios.get(`${API_BASE}/${endpoint}`, params).catch((err) => {
              if (err.response && err.response.status === 404) {
                return { data: { status: "scanning" } }; // Treat 404 as scanning
              } else {
                throw err;
              }
            })
          )
        );

        const [
          hostsRes,
          tcpRes,
          udpRes,
          icmpRes,
          osRes,
          packetsRes,
          firewallRes,
          serviceRes,
        ] = responses.map((res) => res.data);

        const isStillScanning = [
          hostsRes,
          tcpRes,
          udpRes,
          icmpRes,
          osRes,
          packetsRes,
          firewallRes,
          serviceRes,
        ].some((res) => res?.status === "scanning");

        if (isStillScanning) {
          setScanning(true);
        } else {
          setScanning(false);
          clearInterval(interval); // Stop polling
          setHosts(hostsRes || []);
          setTcpResults(tcpRes || []);
          setUdpResults(udpRes || []);
          setIcmpResults(icmpRes || []);
          setOsResults(osRes || []);
          setPackets(packetsRes || []);
          setFirewallResults(firewallRes || []);
          setServiceResults(serviceRes || []);
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        setScanning(false);
        clearInterval(interval);
      }
    };

    // Poll every 3 seconds
    fetchData();
    interval = setInterval(fetchData, 3000);

    return () => clearInterval(interval); // Cleanup
  }, [ip]);
  

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [packets]);

  const uniquePackets = useMemo(() => {
    const seen = new Set();
    return packets.filter((pkt) => {
      if (!seen.has(pkt.packet_summary)) {
        seen.add(pkt.packet_summary);
        return true;
      }
      return false;
    });
  }, [packets]);

  const graphData = packets.map((pkt, index) => ({
    id: pkt.id || index,
    value: pkt.size || Math.random() * 100,
    timestamp: pkt.timestamp || index,
  }));

  const groupedServices = useMemo(() => {
    return serviceResults.reduce((acc, service) => {
      if (!acc[service.host_id]) {
        acc[service.host_id] = [];
      }
      acc[service.host_id].push(service);
      return acc;
    }, {});
  }, [serviceResults]);
  return (
    <div className="dashboard">
      {scanning ? (
        <div className="loader-overlay">
          <div className="loader"></div>
          <p>Scanning in progress. Please wait...</p>
        </div>
      ) : (
        <div className="grid-container">
          <div className="panel host-card">
            <div className="host-header">
              <span className="icon">⚠️</span>
              <p>Hosts Detected</p>
            </div>
            <h1>{hosts.length}</h1>
            <div className="host-list">
              {hosts.length > 0 ? (
                hosts.map((host, index) => (
                  <div key={index} className="host-item">
                    <p>
                      📍 <strong>{host.host || "Unknown IP"}</strong>
                    </p>
                    <p>⏳ {host.last_scanned || "Unknown Time"}</p>
                  </div>
                ))
              ) : (
                <p className="no-hosts">No hosts detected</p>
              )}
            </div>
          </div>

          <div className="panel chart">
            <h2>📡 ICMP RESPONSES</h2>
            {icmpResults.length > 0 ? (
              <div className="icmp-bars">
                {icmpResults.flatMap((icmp, index) => {
                  let responses = [];
                  try {
                    responses = JSON.parse(icmp.icmp_responses);
                  } catch (error) {
                    console.error("Error parsing ICMP responses:", error);
                  }

                  return responses.map((response, i) => {
                    const color =
                      colors[(index * responses.length + i) % colors.length];

                    return (
                      <div key={`${index}-${i}`} className="icmp-bar">
                        <div className="icmp-details">
                          <strong>Host:</strong> {response.host} |
                          <strong> Type:</strong> {response.type} |
                          <strong> Code:</strong> {response.code}
                        </div>
                        <div
                          className="icmp-fill"
                          style={{ background: color }}
                        >
                          {response.description}
                        </div>
                      </div>
                    );
                  });
                })}
              </div>
            ) : (
              <p>No ICMP responses detected</p>
            )}
          </div>

          <div className="panel chart">
            <h2>🌍 TCP Scan Results</h2>
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
                <p className="cyberpunk-no-results">No TCP results available</p>
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

          <div className="panel firewall-container">
            <h2>🛑 Firewall Detection</h2>
            {firewallResults.length > 0 ? (
              <div className="firewall-grid">
                {firewallResults.map((result, index) => (
                  <div key={index} className="firewall-box">
                    <h3>Host {result.host_id}</h3>

                    <div className="firewall-status">
                      <p>
                        <strong>TCP SYN Responses:</strong>{" "}
                        {result.tcp_syn_responses || "N/A"}
                      </p>
                      <p>
                        <strong>ICMP Responses:</strong>{" "}
                        {result.icmp_response || "N/A"}
                      </p>
                      <p>
                        <strong>Port 443 Response:</strong>{" "}
                        {result.port_443_response || "N/A"}
                      </p>
                    </div>

                    <div className="firewall-analysis">
                      <h4>🔥 Analysis</h4>
                      <p>{result.conclusion || "No analysis available"}</p>
                    </div>

                    <div
                      className={`firewall-conclusion ${
                        result.firewall_detected
                          ? "firewall-alert"
                          : "firewall-safe"
                      }`}
                    >
                      <p>
                        {result.firewall_detected
                          ? "🚨 Firewall Detected"
                          : "❌ No Firewall Detected"}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p>No firewall results available</p>
            )}
          </div>

          <div className="panel os-fingerprint">
            <h2 className="title">💻 OS Fingerprinting</h2>
            {osResults.length > 0 ? (
              <div className="os-list">
                {osResults.map((os, index) => (
                  <div className="os-card" key={index}>
                    <h3 className="os-guess">{os.os_guess || "Unknown"}</h3>
                    <p className="details">
                      <span>🖥️ Window Size:</span> {os.window_size || "N/A"}
                    </p>
                    <p className="details">
                      <span>📡 TTL:</span> {os.ttl || "N/A"}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">No OS data available</p>
            )}
          </div>

          <div className="service-container panel">
            <h2 className="title">🔧 Detected Services</h2>
            {Object.keys(groupedServices).length === 0 ? (
              <p className="no-data">No services detected.</p>
            ) : (
              Object.entries(groupedServices).map(([hostId, services]) => (
                <div key={hostId} className="host-card">
                  <h3 className="host-title">🔗 Host ID: {hostId}</h3>
                  <table className="service-table">
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Service</th>
                      </tr>
                    </thead>
                    <tbody>
                      {services.map(({ id, port, service }) => (
                        <tr key={id}>
                          <td>{port}</td>
                          <td>{service}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))
            )}
          </div>

          <div className="cyber-holo-container panel">
            <h2 className="holo-title">📡 PACKET STREAM</h2>

            <div className="holo-log" ref={logRef}>
              {uniquePackets.length > 0 ? (
                uniquePackets.map((pkt, index) => (
                  <p key={index} className={`packet-entry ${pkt.type}`}>
                    <span className="packet-id">
                      [{pkt.id || `#${index + 1}`}]
                    </span>
                    <span className="packet-summary">
                      {" "}
                      {pkt.packet_summary || "No data"}{" "}
                    </span>
                    <span className="packet-timestamp">
                      ⏱ {pkt.timestamp || "Unknown"}
                    </span>
                  </p>
                ))
              ) : (
                <p className="no-packets">Waiting for packets...</p>
              )}
            </div>

            <div className="holo-graph">
              <ResponsiveContainer width="100%" height={150}>
                <LineChart data={graphData}>
                  <XAxis dataKey="timestamp" tick={false} />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke="#00ffff"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      <div className="generate-report-container">
        <button className="gaming-button" onClick={handleGenerateReport}>
          Generate Report
        </button>
      </div>
    </div>
  );
};

export default Dashboard;
