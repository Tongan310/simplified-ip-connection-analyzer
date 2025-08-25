# simplified-ip-connection-analyzer
Splunk dashboard for analyzing network connections with filters, summaries, drilldowns, and regex-based exclusions. Generic, reusable, and safe to share.

---

# Simplified IP Connection Analyzer

A Splunk dashboard to analyze network connections with filters for IPs, status, protocols, and indices. Includes activity view, summaries, drilldowns, and regex-based exclusions. Generic, reusable, and safe for public sharing.

## Features
- Flexible filtering: Source/Destination IP, Protocol, Status, Sourcetype, Index
- Simplified Activity View: timestamped events with normalized fields
- Connection Summary: aggregated counts + drilldowns
- Custom Exclusions: regex-based filters to hide lab/test systems
- Visual highlights: color-coding for Permit/Deny/Unknown

---

## Installation
import into Splunk:

Splunk > Dashboards > Create New > Import XML

Paste the contents of dashboard.xml
