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


---

## 🧩 `dashboard.xml`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<dashboard version="1.1" theme="dark">
  <label>Simplified IP Connection Analyzer</label>
  <description>A streamlined Splunk dashboard for analyzing network connections across multiple data sources, with filtering, drilldowns, and easy-to-read summaries.</description>

  <fieldset submitButton="true" autoRun="false">
    <input type="text" token="source_ip_address" searchWhenChanged="false">
      <label>Source IP Address</label>
      <default></default>
    </input>

    <input type="text" token="dest_ip_address" searchWhenChanged="false">
      <label>Destination IP Address</label>
      <default></default>
    </input>

    <input type="dropdown" token="time_range">
      <label>Time Range</label>
      <choice value="5m">Last 5 minutes</choice>
      <choice value="10m">Last 10 minutes</choice>
      <choice value="15m">Last 15 minutes</choice>
      <choice value="30m">Last 30 minutes</choice>
      <choice value="1h">Last 1 hour</choice>
      <choice value="4h">Last 4 hours</choice>
      <choice value="12h">Last 12 hours</choice>
      <choice value="24h">Last 24 hours</choice>
      <choice value="7d">Last 7 days</choice>
      <choice value="30d">Last 30 days</choice>
      <default>24h</default>
    </input>

    <input type="dropdown" token="connection_status">
      <label>Connection Status</label>
      <choice value="*">All</choice>
      <choice value="Permit">Permit</choice>
      <choice value="Deny">Deny</choice>
      <default>*</default>
    </input>

    <input type="dropdown" token="sourcetype_filter">
      <label>Sourcetype</label>
      <default>*</default>
      <choice value="*">All</choice>
      <choice value="pan:traffic">PAN Traffic</choice>
      <choice value="cisco:asa">Cisco ASA</choice>
      <choice value="wineventlog">Windows Event Log</choice>
      <choice value="linux:secure">Linux Secure</choice>
    </input>

    <input type="dropdown" token="index_filter">
      <label>Index</label>
      <default>*</default>
      <choice value="*">All</choice>
      <choice value="main">main</choice>
      <choice value="firewall">firewall</choice>
      <choice value="endpoint">endpoint</choice>
      <choice value="network">network</choice>
    </input>

    <input type="dropdown" token="protocol_filter">
      <label>Protocol</label>
      <default>*</default>
      <choice value="*">All</choice>
      <choice value="tcp">TCP</choice>
      <choice value="udp">UDP</choice>
      <choice value="icmp">ICMP</choice>
      <choice value="http">HTTP</choice>
    </input>

    <!-- Generic exclusion regex (safe for public use). Example: (?i)(dev|lab|dc1|dc2|test) -->
    <input type="text" token="exclude_patterns" searchWhenChanged="false">
      <label>Exclude host/name patterns (regex)</label>
      <default></default>
    </input>
  </fieldset>

  <!-- Base search -->
  <search id="base_search">
    <query>
index=$index_filter$ $sourcetype_filter$
| eval source_ip=coalesce(src_ip, src, source_ip, sourceAddress)
| eval dest_ip=coalesce(dest_ip, dst, dest, destination_ip, destinationAddress)
| eval source_port=coalesce(src_port, spt, source_port, sourcePort)
| eval dest_port=coalesce(dest_port, dpt, destination_port, destinationPort)
| eval Protocol=coalesce(app_proto, app, application, proto, protocol)
| eval action_raw=lower(coalesce(action, disposition, status, outcome, result))
| eval status=case(
    match(action_raw, "(?i)allow|permit|accept|success|established"), "Permit",
    match(action_raw, "(?i)deny|block|drop|reject|fail"), "Deny",
    true(), "Unknown"
)
| eval event_name=coalesce(event_name, "CONNECTION_STATISTICS")
| eval log_source=coalesce(source, host, log_source)
| eval username=coalesce(user, user_name, username)
| eval category=coalesce(category, "Firewall")
| eval host_lower=lower(coalesce(host,""))
| eval dest_host_lower=lower(coalesce(dest_host, ""))
| eval dest_name_lower=lower(coalesce(dest_name, ""))

| eval match_source=if(isnotnull("$source_ip_address$") AND "$source_ip_address$"!="", if(source_ip="$source_ip_address$",1,0), 1)
| eval match_dest=if(isnotnull("$dest_ip_address$") AND "$dest_ip_address$"!="", if(dest_ip="$dest_ip_address$",1,0), 1)
| where match_source=1 AND match_dest=1

| eval match_status=if("$connection_status$"="*", 1, if(status="$connection_status$",1,0))
| eval match_protocol=if("$protocol_filter$"="*", 1, if(Protocol="$protocol_filter$",1,0))
| where match_status=1 AND match_protocol=1

| eval exclude_ok=if("$exclude_patterns$"!="",
    if(match(host_lower, "$exclude_patterns$") OR match(dest_host_lower, "$exclude_patterns$") OR match(dest_name_lower, "$exclude_patterns$"), 0, 1),
    1)
| where exclude_ok=1
    </query>
    <earliest>-$time_range$</earliest>
    <latest>now</latest>
  </search>

  <row>
    <panel>
      <title>Simplified Activity View</title>
      <table>
        <search base="base_search">
          <query>
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S %Z")
| table Time, event_name, log_source, status, category, source_ip, source_port, dest_ip, dest_port, username, Protocol
| rename event_name as "Event Name", log_source as "Log Source", status as "Action", category as "Category", source_ip as "Source IP", source_port as "Source Port", dest_ip as "Destination IP", dest_port as "Destination Port", username as "Username", Protocol as "Protocol"
| sort - Time
          </query>
        </search>
        <option name="wrap">true</option>
        <option name="rowNumbers">false</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">20</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Connection Summary</title>
      <table>
        <search base="base_search">
          <query>
| stats count by source_ip, dest_ip, dest_port, Protocol, status
| rename source_ip as "Source IP", dest_ip as "Destination IP", dest_port as "Port", Protocol as "Protocol", status as "Status", count as "Count"
| sort - Count
          </query>
        </search>
        <option name="wrap">true</option>
        <option name="drilldown">row</option>
        <option name="dataOverlayMode">none</option>
        <option name="count">20</option>
        <drilldown>
          <set token="drilldown_src">$row.Source IP$</set>
          <set token="drilldown_dst">$row.Destination IP$</set>
          <set token="drilldown_port">$row.Port$</set>
        </drilldown>
      </table>
    </panel>
  </row>

  <row depends="$drilldown_src$">
    <panel>
      <title>Detailed Connection: $drilldown_src$ → $drilldown_dst$ (Port: $drilldown_port$)</title>
      <table>
        <search>
          <query>
index=$index_filter$ $sourcetype_filter$
| eval source_ip=coalesce(src_ip, src, source_ip, sourceAddress)
| eval dest_ip=coalesce(dest_ip, dst, dest, destination_ip, destinationAddress)
| eval dest_port=coalesce(dest_port, dpt, destination_port, destinationPort)
| where source_ip="$drilldown_src$" AND dest_ip="$drilldown_dst$" AND dest_port="$drilldown_port$"
| eval host_lower=lower(coalesce(host,""))
| eval dest_host_lower=lower(coalesce(dest_host, ""))
| eval dest_name_lower=lower(coalesce(dest_name, ""))
| eval exclude_ok=if("$exclude_patterns$"!="",
    if(match(host_lower, "$exclude_patterns$") OR match(dest_host_lower, "$exclude_patterns$") OR match(dest_name_lower, "$exclude_patterns$"), 0, 1),
    1)
| where exclude_ok=1
| eval Timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S %Z")
| eval protocol=coalesce(proto, protocol)
| table Timestamp, source_ip, dest_ip, dest_port, protocol, action, bytes_in, bytes_out, host, source
| rename source_ip as "Source IP", dest_ip as "Destination IP", dest_port as "Destination Port", protocol as "Protocol", action as "Action", bytes_in as "Bytes In", bytes_out as "Bytes Out", host as "Host", source as "Source"
| sort - Timestamp
          </query>
          <earliest>-$time_range$</earliest>
          <latest>now</latest>
        </search>
        <option name="count">20</option>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <html>
        <style>
          .permit-cell {
            color: #00ff00 !important;
            background-color: rgba(0, 128, 0, 0.1);
          }
          .deny-cell {
            color: #ff6666 !important;
            background-color: rgba(255, 0, 0, 0.1);
          }
          .unknown-cell {
            color: #cccccc !important;
            background-color: rgba(128, 128, 128, 0.1);
          }
          .dashboard-table .table-responsive {
            overflow-x: auto;
            max-height: 500px;
            overflow-y: auto;
          }
        </style>

        <script>
          require([
            'jquery',
            'splunkjs/mvc',
            'splunkjs/mvc/simplexml/ready!'
          ], function($, mvc) {
            function applyHighlighting() {
              $('.dashboard-cell table td').each(function() {
                var $cell = $(this);
                var text = ($cell.text() || '').trim();
                if (text === 'Permit') {
                  $cell.addClass('permit-cell');
                } else if (text === 'Deny') {
                  $cell.addClass('deny-cell');
                } else if (text === 'Unknown') {
                  $cell.addClass('unknown-cell');
                }
              });
            }
            setTimeout(applyHighlighting, 500);
            $('.dashboard-cell').on('updateFinished', function() {
              setTimeout(applyHighlighting, 300);
            });
          });
        </script>
      </html>
    </panel>
  </row>
</dashboard>
