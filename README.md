# simplified-ip-connection-analyzer
Splunk dashboard for analyzing network connections with filters, summaries, drilldowns, and regex-based exclusions. Generic, reusable, and safe to share.

A Splunk dashboard to analyze network connections with filters for IPs, status, protocols, and indices. Includes activity view, summaries, drilldowns, and regex-based exclusions. Generic, reusable, and safe for public sharing.

---

## Features
- **Flexible filtering**: Source IP, Destination IP, Protocol, Status, Sourcetype, Index.  
- **Simplified Activity View**: Timestamped events with normalized fields.  
- **Connection Summary**: Aggregated counts + drilldowns for deeper inspection.  
- **Custom Exclusions**: Regex-based filters to hide lab/test systems.  
- **Visual Highlights**: Inline color coding for `Permit`, `Deny`, `Unknown`.  

---

## Installation
1. Clone this repo:
   ```bash
   git clone https://github.com/Tongan310/simplified-ip-connection-analyzer.git
