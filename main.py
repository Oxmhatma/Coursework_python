import os
import re
import csv
import json
import psutil
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt


# ==========================================================
# ADVANCED THREAT HUNTING & FORENSIC ANALYSIS TOOLKIT
# ==========================================================

class AdvancedThreatToolkit:

    def __init__(self):
        self.ioc_file = "iocs.txt"
        self.bruteforce_threshold = 3

    # ------------------------------------------------------
    # Load IOCs
    # ------------------------------------------------------
    def load_iocs(self):
        try:
            with open(self.ioc_file, "r") as file:
                return [line.strip().lower() for line in file if line.strip()]
        except FileNotFoundError:
            return []

    # ------------------------------------------------------
    # Parse Logs
    # ------------------------------------------------------
    def parse_logs(self, file_path):
        events = []
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.+)"

        with open(file_path, "r") as file:
            for line in file:
                match = re.match(pattern, line.strip())
                if match:
                    timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                    message = match.group(2)
                    events.append({
                        "timestamp": timestamp,
                        "message": message.lower()
                    })
        return events

    # ------------------------------------------------------
    # Severity Scoring
    # ------------------------------------------------------
    def assign_severity(self, message):
        if "malware" in message or "unauthorized access" in message:
            return "Critical"
        elif "failed login" in message:
            return "High"
        elif "scan" in message:
            return "Medium"
        else:
            return "Low"

    # ------------------------------------------------------
    # Threat Classification
    # ------------------------------------------------------
    def classify_threat(self, message):
        if "failed login" in message:
            return "Brute Force Attack"
        elif "malware" in message:
            return "Malware Execution"
        elif "scan" in message:
            return "Reconnaissance"
        elif "unauthorized" in message:
            return "Privilege Escalation"
        else:
            return "Normal Activity"

    # ------------------------------------------------------
    # IOC Detection
    # ------------------------------------------------------
    def detect_iocs(self, events, iocs):
        detections = []

        for event in events:
            for ioc in iocs:
                if ioc in event["message"]:
                    severity = self.assign_severity(event["message"])
                    threat_type = self.classify_threat(event["message"])

                    detections.append({
                        "timestamp": event["timestamp"],
                        "ioc": ioc,
                        "message": event["message"],
                        "severity": severity,
                        "threat_type": threat_type
                    })
        return detections

    # ------------------------------------------------------
    # Brute Force Detection
    # ------------------------------------------------------
    def detect_bruteforce(self, events):
        failed_logins = [e for e in events if "failed login" in e["message"]]
        if len(failed_logins) >= self.bruteforce_threshold:
            return True, len(failed_logins)
        return False, len(failed_logins)

    # ------------------------------------------------------
    # Anomaly Detection (Simple)
    # ------------------------------------------------------
    def detect_anomalies(self, events):
        late_night_events = [
            e for e in events if e["timestamp"].hour < 5
        ]
        return late_night_events

    # ------------------------------------------------------
    # Process Scanner
    # ------------------------------------------------------
    def scan_processes(self):
        suspicious_keywords = ["powershell", "cmd.exe", "nmap", "nc.exe"]
        suspicious = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                for keyword in suspicious_keywords:
                    if keyword in name:
                        suspicious.append(proc.info)
            except:
                continue

        return suspicious

    # ------------------------------------------------------
    # Timeline
    # ------------------------------------------------------
    def build_timeline(self, events):
        return sorted(events, key=lambda x: x["timestamp"])

    # ------------------------------------------------------
    # CSV Report
    # ------------------------------------------------------
    def generate_csv_report(self, timeline, detections, processes):
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        with open(filename, "w", newline="") as file:
            writer = csv.writer(file)

            writer.writerow(["Timestamp", "Message"])
            for event in timeline:
                writer.writerow([event["timestamp"], event["message"]])

            writer.writerow([])
            writer.writerow(["IOC", "Threat Type", "Severity"])
            for d in detections:
                writer.writerow([d["ioc"], d["threat_type"], d["severity"]])

            writer.writerow([])
            writer.writerow(["Suspicious Processes"])
            for p in processes:
                writer.writerow([p["pid"], p["name"]])

        return filename

    # ------------------------------------------------------
    # JSON Report
    # ------------------------------------------------------
    def generate_json_report(self, detections):
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as file:
            json.dump(detections, file, default=str, indent=4)
        return filename

    # ------------------------------------------------------
    # Graph Visualization
    # ------------------------------------------------------
    def generate_graph(self, detections):
        severity_counts = Counter([d["severity"] for d in detections])

        plt.figure()
        plt.bar(severity_counts.keys(), severity_counts.values())
        plt.title("Threat Severity Distribution")
        plt.xlabel("Severity Level")
        plt.ylabel("Count")
        plt.show()

    # ------------------------------------------------------
    # Main Analysis Engine
    # ------------------------------------------------------
    def run_analysis(self, log_file):
        events = self.parse_logs(log_file)
        iocs = self.load_iocs()
        detections = self.detect_iocs(events, iocs)
        timeline = self.build_timeline(events)
        processes = self.scan_processes()

        bruteforce_alert, count = self.detect_bruteforce(events)
        anomalies = self.detect_anomalies(events)

        csv_report = self.generate_csv_report(timeline, detections, processes)
        json_report = self.generate_json_report(detections)

        return {
            "total_events": len(events),
            "detections": len(detections),
            "bruteforce": bruteforce_alert,
            "failed_count": count,
            "anomalies": len(anomalies),
            "csv": csv_report,
            "json": json_report,
            "detections_data": detections
        }


# ==========================================================
# GUI SECTION
# ==========================================================

class ToolkitGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Threat Hunting Toolkit")
        self.root.geometry("700x500")

        self.toolkit = AdvancedThreatToolkit()
        self.log_file = None

        self.build_ui()

    def build_ui(self):

        tk.Label(self.root, text="Advanced Threat Hunting & Forensic Toolkit",
                 font=("Arial", 15, "bold")).pack(pady=15)

        tk.Button(self.root, text="Select Log File",
                  command=self.select_file, width=25).pack(pady=5)

        tk.Button(self.root, text="Run Analysis",
                  command=self.run_analysis, width=25, bg="darkblue", fg="white").pack(pady=10)

        tk.Button(self.root, text="Show Severity Graph",
                  command=self.show_graph, width=25).pack(pady=5)

        self.output = tk.Text(self.root, height=15, width=85)
        self.output.pack(pady=10)

    def select_file(self):
        self.log_file = filedialog.askopenfilename(
            filetypes=[("Log Files", "*.log")]
        )

    def run_analysis(self):
        if not self.log_file:
            messagebox.showerror("Error", "Select log file first.")
            return

        results = self.toolkit.run_analysis(self.log_file)

        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, f"Total Events: {results['total_events']}\n")
        self.output.insert(tk.END, f"Threat Detections: {results['detections']}\n")
        self.output.insert(tk.END, f"Failed Login Count: {results['failed_count']}\n")
        self.output.insert(tk.END, f"Brute Force Alert: {results['bruteforce']}\n")
        self.output.insert(tk.END, f"Anomalies Detected: {results['anomalies']}\n\n")
        self.output.insert(tk.END, f"CSV Report: {results['csv']}\n")
        self.output.insert(tk.END, f"JSON Report: {results['json']}\n")

        self.detections_data = results["detections_data"]

    def show_graph(self):
        if hasattr(self, "detections_data"):
            self.toolkit.generate_graph(self.detections_data)
        else:
            messagebox.showerror("Error", "Run analysis first.")


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = ToolkitGUI(root)
    root.mainloop()
