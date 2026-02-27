import argparse
import sys
import threading
import subprocess
from src.core.parser import UniversalParser
from src.core.live_agent import LiveAgent
from src.engine.scoring import get_scoring_engine
from src.engine.reporting import generate_secure_report

def run_static_analysis(filepath: str, output_report: str):
    print(f"\n[+] Starting Static Analysis on: {filepath}")
    parser = UniversalParser()
    try:
        parser.parse(filepath)
        print("\n[+] Analysis Complete.")
    except Exception as e:
        print(f"[-] Analysis Failed: {e}")
        return

    # Generate Report
    engine = get_scoring_engine()
    report_data = engine.generate_report()
    generate_secure_report(report_data, output_report)

def run_live_agent(watch_dir: str, output_report: str):
    print(f"\n[+] Starting Live Agent Monitoring: {watch_dir}")
    print("[+] Press Ctrl+C to stop and generate report.")
    
    agent = LiveAgent(watch_dir=watch_dir)
    
    try:
        agent.start() # Blocks until stopped
    except KeyboardInterrupt:
        print("\n[*] Stopping Live Agent...")
    finally:
        agent.stop()
        print("\n[+] Generating final session report...")
        engine = get_scoring_engine()
        report_data = engine.generate_report()
        generate_secure_report(report_data, output_report)

def launch_dashboard():
    # Helper to launch streamlit
    print("[+] Launching Streamlit Dashboard...")
    subprocess.Popen([sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py"])

def main():
    parser = argparse.ArgumentParser(description="Universal Anti-Forensics Detection Engine")
    
    subparsers = parser.add_subparsers(dest="mode", help="Modes of operation")
    
    # Static mode
    static_parser = subparsers.add_parser("static", help="Analyze a static artifact (disk, pcap, ram, log)")
    static_parser.add_argument("-f", "--file", required=True, help="Path to the artifact file")
    static_parser.add_argument("-o", "--output", default="report.json", help="Output report JSON path")
    static_parser.add_argument("--ui", action="store_true", help="Launch Streamlit dashboard after analysis")
    
    # Live mode
    live_parser = subparsers.add_parser("live", help="Start real-time system monitoring")
    live_parser.add_argument("-d", "--dir", default=".", help="Directory to monitor for file changes (default: current)")
    live_parser.add_argument("-o", "--output", default="live_report.json", help="Output report JSON path continuously updated")
    live_parser.add_argument("--ui", action="store_true", help="Launch Streamlit dashboard immediately")

    args = parser.parse_args()

    if args.mode == "static":
        run_static_analysis(args.file, args.output)
        if args.ui:
            launch_dashboard()
            
    elif args.mode == "live":
        if args.ui:
            # Launch UI in background, UI auto-refreshes if set
             t = threading.Thread(target=launch_dashboard, daemon=True)
             t.start()
        run_live_agent(args.dir, args.output)
        
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
