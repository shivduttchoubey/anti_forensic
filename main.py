import argparse
import sys
import threading
import subprocess
import os
from src.core.parser import UniversalParser
from src.core.live_agent import LiveAgent
from src.engine.scoring import get_scoring_engine
from src.engine.reporting import generate_secure_report

class ForensicFramework:
    def __init__(self):
        self.parser = UniversalParser()
        self.engine = get_scoring_engine()

    def run_static(self, filepath: str, output_report: str = "report.json"):
        print(f"\n[+] Executing Master Static Analysis: {filepath}")
        self.parser.parse(filepath)
        report_data = self.engine.generate_report()
        generate_secure_report(report_data, output_report)
        return report_data

    def run_live(self, watch_dir: str, output_report: str = "live_report.json"):
        agent = LiveAgent(watch_dir=watch_dir)
        try:
            agent.start()
        except KeyboardInterrupt:
            pass
        finally:
            agent.stop()
        
        report_data = self.engine.generate_report()
        generate_secure_report(report_data, output_report)
        return report_data

def launch_dashboard():
    # Fix command for Windows pathing if needed, but sys.executable -m streamlit is best
    cmd = [sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py"]
    subprocess.Popen(cmd, cwd=os.getcwd())

def main():
    parser = argparse.ArgumentParser(description="Anti-Forensic Analysis Framework")
    subparsers = parser.add_subparsers(dest="mode")
    
    static_p = subparsers.add_parser("static")
    static_p.add_argument("-f", "--file", required=True)
    static_p.add_argument("--ui", action="store_true")
    
    live_p = subparsers.add_parser("live")
    live_p.add_argument("-d", "--dir", default=".")
    live_p.add_argument("--ui", action="store_true")
    
    # Just dashboard
    subparsers.add_parser("dashboard")

    args = parser.parse_args()
    framework = ForensicFramework()

    if args.mode == "static":
        framework.run_static(args.file)
        if args.ui: launch_dashboard()
    elif args.mode == "live":
        if args.ui: threading.Thread(target=launch_dashboard, daemon=True).start()
        framework.run_live(args.dir)
    elif args.mode == "dashboard" or not args.mode:
        launch_dashboard()

if __name__ == "__main__":
    main()
