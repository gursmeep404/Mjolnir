import React, { useEffect, useState, useMemo } from "react";
import axios from "axios";
import { Line, Pie, Bar } from "react-chartjs-2";
import { Chart } from "chart.js/auto";
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
        const [hostsRes, tcpRes, udpRes, icmpRes, osRes, packetsRes] =
          await Promise.all([
            axios.get(`${API_BASE}/hosts`),
            axios.get(`${API_BASE}/tcp_results`),
            axios.get(`${API_BASE}/udp_results`),
            axios.get(`${API_BASE}/icmp_results`),
            axios.get(`${API_BASE}/os_results`),
            axios.get(`${API_BASE}/packets`),
          ]);

        setHosts(hostsRes.data);
        setTcpResults(tcpRes.data);
        setUdpResults(udpRes.data);
        setIcmpResults(icmpRes.data);
        setOsResults(osRes.data);
        setPackets(packetsRes.data);
      } catch (error) {
        console.error("Error fetching data", error);
      }
    };

    fetchData();
  }, []);

  // Chart Data
  const tcpChartData = useMemo(
    () => ({
      labels: tcpResults.map((p) => p.port),
      datasets: [
        {
          label: "Open TCP Ports",
          data: tcpResults.map(() => 1),
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
      labels: icmpResults.map((i) => i.ip),
      datasets: [
        {
          label: "Ping Response Time (ms)",
          data: icmpResults.map((i) => i.response_time),
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
            {hosts.map((host, index) => (
              <li key={index}>
                {host.ip} - {host.mac}
              </li>
            ))}
          </ul>
        </div>

        <div className="panel chart">
          <h2>🌐 Open TCP Ports</h2>
          <Bar data={tcpChartData} options={{ maintainAspectRatio: false }} />
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
            {osResults.map((os, index) => (
              <li key={index}>
                {os.ip} - {os.os_name}
              </li>
            ))}
          </ul>
        </div>

        <div className="panel terminal">
          <h2>📡 Packet Capture (Live)</h2>
          <div className="terminal-feed">
            {packets.slice(0, 10).map((pkt, index) => (
              <p key={index}>
                {pkt.src_ip} ➜ {pkt.dst_ip} [{pkt.protocol}]
              </p>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
