import React, { useEffect, useState, useMemo } from "react";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
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

  // Get unique packet summaries
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

  // Transform packets into data format for graph
  const graphData = packets.map((pkt, index) => ({
    id: pkt.id || index,
    value: pkt.size || Math.random() * 100, // Replace 'size' with an actual numerical value
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

        <div className="panel cyberpunk-tcp-results">
          <h2 className="cyberpunk-heading">🌍 TCP Port Scan Results</h2>
          <div className="cyberpunk-port-grid">
            {tcpResults.length > 0 ? (
              tcpResults.map((result, index) => {
                const openPorts = JSON.parse(result.tcp_open || "[]");
                const filteredPorts = JSON.parse(result.tcp_filtered || "[]");
                const closedPorts = JSON.parse(result.tcp_closed || "[]");

                const totalPorts = Math.max(
                  openPorts.length + filteredPorts.length + closedPorts.length,
                  1
                );

                const openPercentage = (
                  (openPorts.length / totalPorts) *
                  100
                ).toFixed(2);
                const filteredPercentage = (
                  (filteredPorts.length / totalPorts) *
                  100
                ).toFixed(2);
                const closedPercentage = (
                  (closedPorts.length / totalPorts) *
                  100
                ).toFixed(2);

                return (
                  <div key={index} className="cyberpunk-port-box">
                    <h3 className="cyberpunk-subheading">
                      Host {result.host_id}
                    </h3>
                    <div className="cyberpunk-progress-container">
                      {/* Open Ports */}
                      <div className="cyberpunk-progress-item">
                        <div className="cyberpunk-progress-wrapper">
                          <CircularProgressbar
                            value={openPercentage}
                            text={`${openPercentage}%`}
                            styles={buildStyles({
                              textColor: "#0ff",
                              pathColor: "#0ff",
                              trailColor: "#222",
                              strokeLinecap: "round",
                            })}
                          />
                        </div>
                        <p className="cyberpunk-label">🟢 Open Ports</p>
                        <div className="cyberpunk-port-list">
                          {openPorts.length > 0
                            ? openPorts.map((port) => (
                                <span key={port} className="cyberpunk-port-tag">
                                  {port}
                                </span>
                              ))
                            : "None"}
                        </div>
                      </div>

                      {/* Filtered Ports */}
                      <div className="cyberpunk-progress-item">
                        <div className="cyberpunk-progress-wrapper">
                          <CircularProgressbar
                            value={filteredPercentage}
                            text={`${filteredPercentage}%`}
                            styles={buildStyles({
                              textColor: "#f0f",
                              pathColor: "#f0f",
                              trailColor: "#222",
                              strokeLinecap: "round",
                            })}
                          />
                        </div>
                        <p className="cyberpunk-label">🟣 Filtered Ports</p>
                        <div className="cyberpunk-port-list">
                          {filteredPorts.length > 0
                            ? filteredPorts.map((port) => (
                                <span key={port} className="cyberpunk-port-tag">
                                  {port}
                                </span>
                              ))
                            : "None"}
                        </div>
                      </div>

                      {/* Closed Ports */}
                      <div className="cyberpunk-progress-item">
                        <div className="cyberpunk-progress-wrapper">
                          <CircularProgressbar
                            value={closedPercentage}
                            text={`${closedPercentage}%`}
                            styles={buildStyles({
                              textColor: "#f00",
                              pathColor: "#f00",
                              trailColor: "#222",
                              strokeLinecap: "round",
                            })}
                          />
                        </div>
                        <p className="cyberpunk-label">🔴 Closed Ports</p>
                        <p className="cyberpunk-closed-text">
                          {closedPorts.length} ports closed
                        </p>
                      </div>
                    </div>
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

        <div className="panel chart">
          <h2>📡 ICMP RESPONSES</h2>
          {icmpResults.length > 0 ? (
            <div className="icmp-bars">
              {icmpResults.map((icmp, index) => {
                let responses = [];
                try {
                  responses = JSON.parse(icmp.icmp_responses);
                } catch (error) {
                  console.error("Error parsing ICMP responses:", error);
                }

                return responses.map((response, i) => (
                  <div key={`${index}-${i}`} className="icmp-bar">
                    {/* Host, Type, and Code appear ABOVE the bar */}
                    <div className="icmp-details">
                      <strong>Host:</strong> {response.host} |
                      <strong> Type:</strong> {response.type} |
                      <strong> Code:</strong> {response.code}
                    </div>
                    {/* Description inside the bar */}
                    <div className="icmp-fill">{response.description}</div>
                  </div>
                ));
              })}
            </div>
          ) : (
            <p>No ICMP responses detected</p>
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

        {/* Packet Capture Panel */}
        <div className="panel packet-capture">
          <h2>📡 Packet Capture (Live)</h2>
          <div className="packet-grid">
            {uniquePackets.length > 0 ? (
              uniquePackets.map((pkt, index) => (
                <div key={index} className="packet-box">
                  <h3>Packet {pkt.id || index}</h3>

                  {/* Packet Summary Section */}
                  <div className="packet-section">
                    <h4 className="summary-title">📜 Summary</h4>
                    <p className="packet-summary">
                      {pkt.packet_summary || "No summary available"}
                    </p>
                  </div>

                  {/* Timestamp Section */}
                  <div className="packet-section">
                    <h4 className="timestamp-title">⏱ Timestamp</h4>
                    <p className="packet-timestamp">
                      {pkt.timestamp || "Unknown"}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <p>No packets captured</p>
            )}
          </div>

          {/* Graph Visualization */}
          <div className="graph-container">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={graphData}>
                <XAxis dataKey="timestamp" tick={false} />
                <YAxis />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#8A2BE2"
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
