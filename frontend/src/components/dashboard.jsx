import { useEffect, useState } from "react";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
} from "recharts";
import "../../styles/dashboard.css"; // Import your CSS file

const Dashboard = () => {
  const [data, setData] = useState(null);
  const host = "1";

  useEffect(() => {
    axios
      .get(`http://127.0.0.1:5000/scan_results?host=${host}`)
      .then((response) => {
        console.log("Fetched Data:", response.data);
        setData(response.data.scan_results);
      })
      .catch((error) => console.error("Error fetching data:", error));
  }, [host]);

  if (!data) return <div className="text-center">Loading...</div>;

  const formatChartData = (results) =>
    results?.map((entry) => ({
      time: entry.scan_time || entry[1], 
      open_ports: entry.open_ports || entry[0],
    })) || [];

  const tcpData = formatChartData(data.tcp);
  const udpData = formatChartData(data.udp);

  return (
    <div className="container">
      <h1>Scan Results Dashboard</h1>

      <div className="chart-container">
        <h2 className="chart-title">TCP Scan Results</h2>
        <ResponsiveContainer width="100%" height={350}>
          <LineChart data={tcpData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" stroke="#ccc" />
            <YAxis stroke="#ccc" />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="open_ports" stroke="#ff7300" name="TCP Open Ports" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-container">
        <h2 className="chart-title">UDP Scan Results</h2>
        <ResponsiveContainer width="100%" height={350}>
          <LineChart data={udpData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" stroke="#ccc" />
            <YAxis stroke="#ccc" />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="open_ports" stroke="#00ffcc" name="UDP Open Ports" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default Dashboard;
