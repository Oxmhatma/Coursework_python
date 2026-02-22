import os
import re
import csv
import psutil
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime


# =====================================================
# THREAT HUNTING & FORENSIC TOOLKIT
# (Single File + Same Directory Structure)
# =====================================================

class ThreatHuntingToolkit:

    def __init__(self):
        self.ioc_file = "iocs.txt"

    # ---------------------------
    # Load IOCs
    # ---------------------------
    def load_iocs(self):
        try:
            with open(self.ioc_file, "r") as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            return []

    # ---------------------------
    # Parse Logs
    # ---------------------------
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
                        "message": message
                    })
        return events

    # ---------------------------
    # IOC Detection
    # ---------------------------
    def detect_iocs(self, events, iocs):
        matches = []
        for event in events:
            for ioc in iocs:
                if ioc.lower() in event["message"].lower():
                    matches.append({
                        "timestamp": event["timestamp"],
                        "ioc": ioc,
                        "message": event["message"]
                    })
        return matches

    # ---------------------------
    # Timeline
    # ---------------------------
    def build_timeline(self, events):
        return sorted(events, key=lambda x: x["timestamp"])

    # ---------------------------
    # Process Scanner
    # ---------------------------
    def scan_processes(self):
        suspicious = []
        keywords = ["powershell", "cmd.exe", "nmap", "nc.exe"]

        for process in psutil.process_iter(['pid', 'name']):
            try:
                name = process.info['name'].lower()
                for keyword in keywords:
                    if keyword in name:
                        suspicious.append(process.info)
            except:
                continue
        return suspicious

    # ---------------------------
    # Report Generator
    # ---------------------------
    def generate_report(self, timeline, matches, processes):
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        with open(filename, "w", newline="") as file:
            writer = csv.writer(file)

            writer.writerow(["=== Timeline Events ==="])
            writer.writerow(["Timestamp", "Message"])
            for event in timeline:
                writer.writerow([event["timestamp"], event["message"]])

            writer.writerow([])
            writer.writerow(["=== IOC Matches ==="])
            writer.writerow(["Timestamp", "IOC", "Message"])
            for match in matches:
                writer.writerow([match["timestamp"], match["ioc"], match["message"]])

            writer.writerow([])
            writer.writerow(["=== Suspicious Processes ==="])
            writer.writerow(["PID", "Process Name"])
            for proc in processes:
                writer.writerow([proc["pid"], proc["name"]])

        return filename

    # ---------------------------
    # Run Full Analysis
    # ---------------------------
    def run_analysis(self, log_file):
        events = self.parse_logs(log_file)
        iocs = self.load_iocs()
        matches = self.detect_iocs(events, iocs)
        timeline = self.build_timeline(events)
        processes = self.scan_processes()
        report = self.generate_report(timeline, matches, processes)

        return {
            "total_events": len(events),
            "ioc_matches": len(matches),
            "suspicious_processes": len(processes),
            "report_file": report
        }


# =====================================================
# GUI SECTION
# =====================================================

class ThreatToolkitGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Threat Hunting & Forensic Analysis Toolkit")
        self.root.geometry("600x450")

        self.toolkit = ThreatHuntingToolkit()
        self.log_file = None

        self.build_interface()

    def build_interface(self):

        tk.Label(self.root,
                 text="Threat Hunting & Forensic Analysis Toolkit",
                 font=("Arial", 16, "bold")).pack(pady=15)

        tk.Button(self.root,
                  text="Select Log File",
                  command=self.select_file,
                  width=25).pack(pady=10)

        self.file_label = tk.Label(self.root, text="No file selected")
        self.file_label.pack()

        tk.Button(self.root,
                  text="Run Threat Analysis",
                  command=self.run_analysis,
                  bg="#1f4ed8",
                  fg="white",
                  width=25).pack(pady=20)

        self.result_box = tk.Text(self.root, height=10, width=70)
        self.result_box.pack(pady=10)

    def select_file(self):
        self.log_file = filedialog.askopenfilename(
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if self.log_file:
            self.file_label.config(text=self.log_file)

    def run_analysis(self):
        if not self.log_file:
            messagebox.showerror("Error", "Please select a log file first.")
            return

        try:
            results = self.toolkit.run_analysis(self.log_file)

            self.result_box.delete(1.0, tk.END)
            self.result_box.insert(tk.END, f"Total Events: {results['total_events']}\n")
            self.result_box.insert(tk.END, f"IOC Matches: {results['ioc_matches']}\n")
            self.result_box.insert(tk.END, f"Suspicious Processes: {results['suspicious_processes']}\n")
            self.result_box.insert(tk.END, f"\nReport Generated:\n{results['report_file']}")

            messagebox.showinfo("Success", "Threat Analysis Completed Successfully!")

        except Exception as e:
            messagebox.showerror("Error", str(e))


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatToolkitGUI(root)
    root.mainloop()
