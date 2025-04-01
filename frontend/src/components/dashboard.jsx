import React, { useEffect, useState, useMemo, useRef } from "react";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import "react-circular-progressbar/dist/styles.css";

import "../../styles/dashboard.css";

const API_BASE = "http://localhost:5000/api";

const Dashboard = () => {
  const [hosts, setHosts] = useState([]);
  const [tcpResults, setTcpResults] = useState([]);
  const [udpResults, setUdpResults] = useState([]);
  const [icmpResults, setIcmpResults] = useState([]);
  const [osResults, setOsResults] = useState([]);
  const [packets, setPackets] = useState([]);
  const [firewallResults, setFirewallResults] = useState([]);
  const logRef = useRef(null);
  const colors = ["#00a8ff", "#ff4d6d", "#9b5de5", "#fcbf49", "#00c897"];


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
          axios.get(`${API_BASE}/firewall_results`),
        ]);

        const [hostsRes, tcpRes, udpRes, icmpRes, osRes, packetsRes, firewallRes] =
          responses.map((res) => res.data);

        console.log("Fetched Data:", {
          hostsRes,
          tcpRes,
          udpRes,
          icmpRes,
          osRes,
          packetsRes,
          firewallRes,
        });

        setHosts(hostsRes || []);
        setTcpResults(tcpRes || []);
        setUdpResults(udpRes || []);
        setIcmpResults(icmpRes || []);
        setOsResults(osRes || []);
        setPackets(packetsRes || []);
        setFirewallResults(firewallRes || []);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, []);
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


  return (
    <div className="dashboard">
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
                      <div className="icmp-fill" style={{ background: color }}>
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
                    <p >
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
    </div>
  );
};

export default Dashboard;
