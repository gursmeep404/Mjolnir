import React, { useEffect, useState } from "react";
import'../../styles/dashboard.css';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  LineChart,
  Line,
  Legend,
} from "recharts";
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
      <h2>TCP Scan Results</h2>
      <PieChart width={400} height={400}>
        <Pie
          data={[
            {
              name: "Open",
              value: data.tcp_results?.reduce(
                (acc, res) => acc + (res?.tcp_open?.length || 0),
                0
              ),
              color: "#00FFFF", // Neon Cyan
            },
            {
              name: "Closed",
              value: data.tcp_results?.reduce(
                (acc, res) => acc + (res?.tcp_closed?.length || 0),
                0
              ),
              color: "#D100D1", // Neon Purple
            },
            {
              name: "Filtered",
              value: data.tcp_results?.reduce(
                (acc, res) => acc + (res?.tcp_filtered?.length || 0),
                0
              ),
              color: "#FF007F", // Electric Pink
            },
          ]}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          outerRadius={120}
          fill="#8884d8"
          label
        >
          <Cell fill="#00FFFF" /> {/* Neon Cyan */}
          <Cell fill="#D100D1" /> {/* Neon Purple */}
          <Cell fill="#FF007F" /> {/* Electric Pink */}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
      </div>
      </div>
  );
      };

export default Dashboard;

// <div className="card">
//   <h2>TCP Scan Results</h2>
//   <ul>
//     {data.tcp_results?.map((result, index) => (
//       <li key={index}>
//         Open: {result?.tcp_open?.length || 0} | Closed:{" "}
//         {result?.tcp_closed?.length || 0} | Filtered:{" "}
//         {result?.tcp_filtered?.length || 0}
//       </li>
//     ))}
//   </ul>
// </div>

// {/* UDP Scan Bar Chart */}
// <div className="card">
//   <h2>UDP Scan Results</h2>
//   <BarChart
//     width={500}
//     height={300}
//     data={[
//       {
//         name: "UDP",
//         Open: data.udp_results[0]?.udp_open?.length || 0,
//         Closed: data.udp_results[0]?.udp_closed?.length || 0,
//       },
//     ]}
//   >
//     <XAxis dataKey="name" />
//     <YAxis />
//     <Tooltip />
//     <Legend />
//     <Bar dataKey="Open" fill="#82ca9d" />
//     <Bar dataKey="Closed" fill="#8884d8" />
//   </BarChart>
// </div>

{
  /* ICMP Responses Pie Chart */
}
{
  /* <div className="card">
        <h2>ICMP Responses</h2>
        <PieChart width={400} height={300}>
          <Pie
            data={[
              {
                name: "ICMP Responses",
                value: data.icmp_results[0]?.icmp_responses?.length || 0,
              },
            ]}
            cx="50%"
            cy="50%"
            outerRadius={80}
            fill="#ffc658"
            label
          >
            {data.icmp_results[0]?.icmp_responses?.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={COLORS[index % COLORS.length]}
              />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </div> */
}

// {/* Packet Summary Line Chart */}
// <div className="card">
//   <h2>Packet Summary</h2>
//   <LineChart width={500} height={300} data={data.packets}>
//     <XAxis dataKey="timestamp" />
//     <YAxis />
//     <Tooltip />
//     <Legend />
//     <Line type="monotone" dataKey="protocol" stroke="#8884d8" />
//   </LineChart>
// </div>
