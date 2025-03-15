import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Thunderstorm, Scan } from "lucide-react";
import styles from "./MjolnirScanner.module.css"; // Import CSS

export default function MjolnirScanner() {
  return (
    <div className={styles.container}>
      {/* Background Animation */}
      <motion.div
        className={styles.lightning}
        animate={{ opacity: [0.2, 0.5, 0.2] }}
        transition={{ repeat: Infinity, duration: 2 }}
      />

      {/* Flying Ravens */}
      <motion.img
        src="/raven.png"
        className={styles.raven}
        animate={{ x: [0, 300, 0], y: [0, -50, 0] }}
        transition={{ repeat: Infinity, duration: 4, ease: "easeInOut" }}
      />

      {/* Title and Button */}
      <div className={styles.content}>
        <Thunderstorm className={styles.thunderIcon} />
        <h1 className={styles.title}>⚡ Mjolnir ⚡</h1>
        <p className={styles.subtitle}>
          "Striking down vulnerabilities with the power of the gods."
        </p>

        <motion.div whileHover={{ scale: 1.1 }}>
          <Button className={styles.scanButton}>
            <Scan className={styles.icon} /> Start Scan
          </Button>
        </motion.div>
      </div>
    </div>
  );
}
