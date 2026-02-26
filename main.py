import os
import re
import csv
import json
import psutil
import logging
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt


# ==========================================================
# Threat Hunting and Forensic Analysis Toolkit
# ==========================================================

class ThreatHuntingToolkit:

    def __init__(self):
        self.load_config()
        self.setup_logging()

    # ------------------------------------------------------
    # Load Configuration
    # ------------------------------------------------------
    def load_config(self):
        try:
            with open("config.json") as f:
                config = json.load(f)

            self.severity_scores = config["severity_scores"]
            self.bruteforce_threshold = config["bruteforce_threshold"]
            self.suspicious_processes = config["suspicious_processes"]

        except Exception as e:
            raise Exception(f"Config file error: {e}")

    # ------------------------------------------------------
    # Setup Logging
    # ------------------------------------------------------
    def setup_logging(self):
        logging.basicConfig(
            filename="toolkit.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    # ------------------------------------------------------
    # Create Reports Folder
    # ------------------------------------------------------
    def create_report_directory(self):
        today = datetime.now().strftime("%Y-%m-%d")
        report_dir = os.path.join("reports", today)
        os.makedirs(report_dir, exist_ok=True)
        return report_dir

    # ------------------------------------------------------
    # Load Threat Intelligence
    # ------------------------------------------------------
    def load_threat_intel(self):
        try:
            with open("threat_intel.json") as f:
                return json.load(f)
        except Exception as e:
            raise Exception(f"Threat intelligence file error: {e}")

    # ------------------------------------------------------
    # Parse Logs
    # ------------------------------------------------------
    def parse_logs(self, file_path):
        events = []
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.+)"

        with open(file_path) as file:
            for line in file:
                match = re.match(pattern, line.strip())
                if match:
                    timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                    message = match.group(2).lower()
                    events.append({
                        "timestamp": timestamp,
                        "message": message
                    })

        logging.info(f"Parsed {len(events)} events.")
        return events

    # ------------------------------------------------------
    # Assign Severity
    # ------------------------------------------------------
    def assign_severity(self, message):
        if "malware" in message or "unauthorized" in message:
            return "Critical"
        elif "failed login" in message:
            return "High"
        elif "scan" in message:
            return "Medium"
        else:
            return "Low"

    # ------------------------------------------------------
    # Detect Threats
    # ------------------------------------------------------
    def detect_threats(self, events):
        intel = self.load_threat_intel()
        detections = []

        for event in events:
            msg = event["message"]

            for ip in intel.get("malicious_ips", []):
                if ip in msg:
                    detections.append(self.create_detection(event, ip))

            for malware in intel.get("malware_names", []):
                if malware in msg:
                    detections.append(self.create_detection(event, malware))

        logging.info(f"Detected {len(detections)} threats.")
        return detections

    def create_detection(self, event, indicator):
        severity = self.assign_severity(event["message"])
        return {
            "timestamp": event["timestamp"],
            "indicator": indicator,
            "message": event["message"],
            "severity": severity,
            "risk_score": self.severity_scores.get(severity, 0)
        }

    # ------------------------------------------------------
    # Brute Force Detection
    # ------------------------------------------------------
    def detect_bruteforce(self, events):
        failed = [e for e in events if "failed login" in e["message"]]
        return len(failed) >= self.bruteforce_threshold, len(failed)

    # ------------------------------------------------------
    # Process Scan
    # ------------------------------------------------------
    def scan_processes(self):
        suspicious = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                for keyword in self.suspicious_processes:
                    if keyword in name:
                        suspicious.append(proc.info)
            except:
                continue

        return suspicious

    # ------------------------------------------------------
    # Calculate Risk Score
    # ------------------------------------------------------
    def calculate_risk_score(self, detections):
        return sum(d["risk_score"] for d in detections)

    # ------------------------------------------------------
    # Save Reports
    # ------------------------------------------------------
    def save_reports(self, detections):

        report_dir = self.create_report_directory()
        timestamp = datetime.now().strftime("%H%M%S")

        csv_path = os.path.join(report_dir, f"report_{timestamp}.csv")
        json_path = os.path.join(report_dir, f"report_{timestamp}.json")
        graph_path = os.path.join(report_dir, f"severity_{timestamp}.png")

        # CSV
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Indicator", "Severity", "Risk Score"])
            for d in detections:
                writer.writerow([d["indicator"], d["severity"], d["risk_score"]])

        # JSON
        with open(json_path, "w") as f:
            json.dump(detections, f, default=str, indent=4)

        # Graph
        if detections:
            severity_counts = Counter([d["severity"] for d in detections])
            plt.figure()
            plt.bar(severity_counts.keys(), severity_counts.values())
            plt.title("Threat Severity Distribution")
            plt.savefig(graph_path)
            plt.close()
        else:
            graph_path = "No threats detected"

        logging.info("Reports saved.")
        return csv_path, json_path, graph_path

    # ------------------------------------------------------
    # Main Engine
    # ------------------------------------------------------
    def run_analysis(self, log_file):

        events = self.parse_logs(log_file)
        detections = self.detect_threats(events)
        processes = self.scan_processes()
        bruteforce_alert, failed_count = self.detect_bruteforce(events)
        total_risk = self.calculate_risk_score(detections)

        csv_path, json_path, graph_path = self.save_reports(detections)

        return {
            "events": len(events),
            "detections": len(detections),
            "risk_score": total_risk,
            "failed_count": failed_count,
            "bruteforce": bruteforce_alert,
            "csv": csv_path,
            "json": json_path,
            "graph": graph_path
        }


# ==========================================================
# GUI
# ==========================================================

class ToolkitGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Threat Hunting and Forensic Analysis Toolkit")
        self.root.geometry("700x500")

        self.toolkit = ThreatHuntingToolkit()
        self.log_file = None

        self.build_ui()

    def build_ui(self):

        tk.Label(self.root,
                 text="Threat Hunting and Forensic Analysis Toolkit",
                 font=("Arial", 14, "bold")).pack(pady=15)

        tk.Button(self.root,
                  text="Select Log File",
                  command=self.select_file,
                  width=25).pack(pady=5)

        tk.Button(self.root,
                  text="Run Analysis",
                  command=self.run_analysis,
                  width=25,
                  bg="darkblue",
                  fg="white").pack(pady=10)

        self.output = tk.Text(self.root, height=15, width=85)
        self.output.pack(pady=10)

    def select_file(self):
        self.log_file = filedialog.askopenfilename(
            filetypes=[("Log Files", "*.log")]
        )

    def run_analysis(self):

        if not self.log_file:
            messagebox.showerror("Error", "Please select a log file.")
            return

        try:
            results = self.toolkit.run_analysis(self.log_file)

            self.output.delete(1.0, tk.END)
            self.output.insert(tk.END, f"Total Events: {results['events']}\n")
            self.output.insert(tk.END, f"Threat Detections: {results['detections']}\n")
            self.output.insert(tk.END, f"Total Risk Score: {results['risk_score']}\n")
            self.output.insert(tk.END, f"Failed Login Attempts: {results['failed_count']}\n")
            self.output.insert(tk.END, f"Brute Force Alert: {results['bruteforce']}\n\n")
            self.output.insert(tk.END, f"CSV Report: {results['csv']}\n")
            self.output.insert(tk.END, f"JSON Report: {results['json']}\n")
            self.output.insert(tk.END, f"Graph: {results['graph']}\n")

        except Exception as e:
            messagebox.showerror("Error", str(e))


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = ToolkitGUI(root)
    root.mainloop()
