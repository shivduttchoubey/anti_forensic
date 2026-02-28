# Universal Anti-Forensics Detection Engine - Phase 2

This update focuses on making the core analysis more comprehensive and moving the execution control to the Streamlit dashboard for a more user-friendly, "single-pane-of-glass" experience.

## Proposed Changes

### Dashboard-Driven Execution [Phase 2]

#### [MODIFY] src/dashboard/app.py
- **Interactive Controls**: Move from CLI-only execution to dashboard-based triggers.
- **File Upload / Path Selection**: Add UI components to upload artifacts or specify server-side paths for analysis.
- **Live Agent Toggle**: Add buttons to start/stop the background monitoring process directly from the UI.
- **Improved Visualization**: Add charts (e.g., pie charts for anomaly categories) and better progress indicators.

#### [MODIFY] main.py
- **API/Server Mode**: Refactor to allow the dashboard to communicate with the core logic without restarting the process.

### Core Enhancements [Phase 2]

#### [MODIFY] src/analyzers/storage.py
- **Magic Number Validation**: Check file headers (magic bytes) against extensions to detect masquerading.
- **Hidden Streams (NTFS)**: (Conceptual/Basic) Detect traces of Alternate Data Streams if possible.

#### [MODIFY] src/analyzers/network.py
- **ICMP Tunneling**: Detect unusually large ICMP payloads or high frequency.
- **Protocol Mismatches**: Detect traffic on non-standard ports (e.g., HTTP on port 445).

#### [MODIFY] src/core/live_agent.py
- **Registry Monitoring**: Detect clearing of forensic artifacts (Prefetch, RecentDocs, Event Logs) via registry keys or specialized API calls.
- **Thread Safety**: Ensure the agent can be started/stopped reliably from the dashboard thread.

#### [MODIFY] src/engine/scoring.py
- **Weighted Scoring**: Implement a more nuanced scoring system where certain anomalies contribute more to the final category risk.

## Verification Plan

### Automated Tests
- Run automated scripts to trigger registry changes and verify the Live Agent's detection.
- Use mock files with mismatched headers to test the Storage Analyzer enhancement.

### Manual Verification
- Launch the dashboard and perform a complete static analysis workflow (upload -> scan -> report) without using the terminal.
- Start the live agent via the dashboard, perform a "wipe" action, and verify the UI updates in real-time.
