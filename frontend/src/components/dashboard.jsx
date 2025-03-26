import React, { useEffect, useState, useMemo } from "react";
import axios from "axios";
import { Line, Pie, Bar } from "react-chartjs-2";
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
  // Ensure previous chart instances are destroyed
  useEffect(() => {
    return () => {
      tcpChartRef.current?.destroy();
      udpChartRef.current?.destroy();
      icmpChartRef.current?.destroy();
    };
  }, []);
  // Chart Data
  const tcpChartData = useMemo(
    () => ({
      labels: tcpResults.map((p) => p.port || "Unknown"),
      datasets: [
        {
          label: "Open TCP Ports",
          data: tcpResults.map((p) => p.count || 1),
          backgroundColor: "rgba(30, 144, 255, 0.7)",
        },
      ],
    }),
    [tcpResults]
  );

  const udpChartData = useMemo(
    () => ({
      labels: ["Open", "Closed", "Filtered"],
      datasets: [
        {
          data: [
            udpResults.filter((p) => p.status === "open").length,
            udpResults.filter((p) => p.status === "closed").length,
            udpResults.filter((p) => p.status === "filtered").length,
          ],
          backgroundColor: ["#4CAF50", "#FF5733", "#FFC107"],
        },
      ],
    }),
    [udpResults]
  );

  const icmpChartData = useMemo(
    () => ({
      labels: icmpResults.map((i) => i.ip || "Unknown"),
      datasets: [
        {
          label: "Ping Response Time (ms)",
          data: icmpResults.map((i) => i.response_time || 0),
          borderColor: "#ff00ff",
          fill: false,
        },
      ],
    }),
    [icmpResults]
  );

  return (
    <div className="dashboard">
      <header className="title-bar">
        <h1>Cyberpunk Network Scanner</h1>
      </header>

      <div className="grid-container">
        <div className="panel hosts">
          <h2>🖥️ Hosts Detected</h2>
          <p>{hosts.length} Hosts Found</p>
          <ul>
            {hosts.length > 0 ? (
              hosts.map((host, index) => (
                <li key={index}>
                  {host.ip || "Unknown"} - {host.mac || "Unknown"}
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
          <Pie data={udpChartData} options={{ maintainAspectRatio: false }} />
        </div>

        <div className="panel chart">
          <h2>📡 ICMP Responses</h2>
          <Line data={icmpChartData} options={{ maintainAspectRatio: false }} />
        </div>

        <div className="panel os">
          <h2>💻 OS Fingerprinting</h2>
          <ul>
            {osResults.length > 0 ? (
              osResults.map((os, index) => (
                <li key={index}>
                  {os.ip || "Unknown"} - {os.os_name || "Unknown"}
                </li>
              ))
            ) : (
              <p>No OS data available</p>
            )}
          </ul>
        </div>

        <div className="panel terminal">
          <h2>📡 Packet Capture (Live)</h2>
          <div className="terminal-feed">
            {packets.length > 0 ? (
              packets.slice(0, 10).map((pkt, index) => (
                <p key={index}>
                  {pkt.src_ip || "Unknown"} ➜ {pkt.dst_ip || "Unknown"} [
                  {pkt.protocol || "Unknown"}]
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
