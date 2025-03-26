import React, { useEffect, useState } from "react";
import'../../styles/dashboard.css';

const Dashboard = () => {
  const [data, setData] = useState({
    hosts: [],
    arp_results: [],
    tcp_results: [],
    udp_results: [],
    icmp_results: [],
    os_results: [],
    firewall_results: [],
    packets: [],
  });

  useEffect(() => {
    const fetchData = async () => {
      const endpoints = [
        "hosts",
        "arp_results",
        "tcp_results",
        "udp_results",
        "icmp_results",
        "os_results",
        "firewall_results",
        "packets",
      ];

      const results = await Promise.all(
        endpoints.map(async (endpoint) => {
          const res = await fetch(`http://127.0.0.1:5000/api/${endpoint}`);
          return { [endpoint]: await res.json() };
        })
      );

      setData(Object.assign({}, ...results)); // Merge responses into state
    };

    fetchData();
  }, []);

  return (
    <div className="dashboard">
      <h1>Network Scan Results</h1>

      <div className="card">
        <h2>Hosts</h2>
        <ul>
          {data.hosts.map((host, index) => (
            <li key={index}>
              {host.host} (Last Scanned: {host.last_scanned})
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>ARP Scan Results</h2>
        <ul>
          {data.arp_results.map((result, index) => (
            <li key={index}>
              {result.scanned_ip} (Scanned At: {result.scan_time})
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>TCP Scan Results</h2>
        <ul>
          {data.tcp_results.map((result, index) => (
            <li key={index}>
              Open: {result.tcp_open} | Closed: {result.tcp_closed} | Filtered:{" "}
              {result.tcp_filtered}
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>UDP Scan Results</h2>
        <ul>
          {data.udp_results.map((result, index) => (
            <li key={index}>
              Open: {result.udp_open} | Closed: {result.udp_closed} | Filtered:{" "}
              {result.udp_filtered}
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>ICMP Responses</h2>
        <ul>
          {data.icmp_results.map((result, index) => (
            <li key={index}>
              {result.icmp_responses} (Scanned At: {result.scan_time})
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>OS Detection</h2>
        <ul>
          {data.os_results.map((result, index) => (
            <li key={index}>
              TTL: {result.ttl} | Window Size: {result.window_size} | OS Guess:{" "}
              {result.os_guess}
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>Firewall Detection</h2>
        <ul>
          {data.firewall_results.map((result, index) => (
            <li key={index}>
              TCP Responses: {result.tcp_syn_responses} | ICMP:{" "}
              {result.icmp_response} | Conclusion: {result.conclusion}
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>Packet Summary</h2>
        <ul>
          {data.packets.map((packet, index) => (
            <li key={index}>
              {packet.timestamp} - {packet.source_ip} → {packet.destination_ip}{" "}
              ({packet.protocol})
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default Dashboard;
