import os
import subprocess
from datetime import datetime

# Define IP ranges to scan
ip_ranges = ["192.168.2.0/24", "192.168.3.0/24"]

# Define sensitive ports (e.g., FTP, SSH, SMB, RDP, etc.)
sensitive_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt"
}

# Output directory for reports
output_dir = "scan_reports"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Function to run Nmap host discovery
def run_nmap_host_discovery(ip_range):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"host_discovery_{ip_range.replace('/', '_')}_{timestamp}.txt")
    
    # Run Nmap host discovery
    command = [
        "nmap",
        "-sn",  # Ping scan (host discovery only)
        "-oG", output_file,  # Output in grepable format
        ip_range
    ]
    
    print(f"[*] Performing host discovery on {ip_range}...")
    subprocess.run(command, check=True)
    return output_file

# Function to run Nmap port scanning
def run_nmap_port_scan(ip_range):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"port_scan_{ip_range.replace('/', '_')}_{timestamp}.xml")
    
    # Run Nmap port scan with service and version detection
    command = [
        "nmap",
        "-sS",  # TCP SYN scan
        "-p-",  # Scan all ports
        "-sV",  # Service version detection
        "-sC",  # Run default NSE scripts
        "--script=vuln",  # Vulnerability detection
        "-oX", output_file,  # Output in XML format
        ip_range
    ]
    
    print(f"[*] Performing port scan on {ip_range}...")
    subprocess.run(command, check=True)
    return output_file

# Function to parse Nmap XML and generate HTML report
def generate_html_report(xml_file):
    from lxml import etree

    # Parse XML file
    tree = etree.parse(xml_file)
    root = tree.getroot()

    # HTML template
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nmap Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            h1 { color: #333; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #f4f4f4; }
            .sensitive { background-color: #ffcccc; }
            .open { background-color: #ccffcc; }
            .closed { background-color: #f0f0f0; }
        </style>
    </head>
    <body>
        <h1>Nmap Scan Report</h1>
        <p><strong>Scan Date:</strong> {scan_date}</p>
        <p><strong>IP Range:</strong> {ip_range}</p>
        <table>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Service</th>
                <th>State</th>
                <th>Version</th>
                <th>Vulnerabilities</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    # Extract data from XML
    rows = ""
    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name") if service is not None else "unknown"
            service_version = service.get("product") + " " + service.get("version") if service is not None else ""
            state = port.find("state").get("state")
            
            # Check if port is sensitive
            port_class = "sensitive" if int(port_id) in sensitive_ports else "open"
            if state == "closed":
                port_class = "closed"
            
            # Extract vulnerabilities
            vulnerabilities = []
            for script in port.findall("script"):
                if script.get("id") == "vuln":
                    vulnerabilities.append(script.get("output"))
            
            # Add row to HTML
            rows += f"""
            <tr class="{port_class}">
                <td>{ip}</td>
                <td>{port_id}</td>
                <td>{service_name}</td>
                <td>{state}</td>
                <td>{service_version}</td>
                <td>{'<br>'.join(vulnerabilities) if vulnerabilities else 'None'}</td>
            </tr>
            """

    # Generate HTML report
    html_report = html_template.format(
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_range=os.path.basename(xml_file).split("_")[2].replace("_", "/"),
        rows=rows
    )

    # Save HTML report
    html_file = xml_file.replace(".xml", ".html")
    with open(html_file, "w") as f:
        f.write(html_report)
    
    print(f"[+] HTML report generated: {html_file}")

# Main function
def main():
    for ip_range in ip_ranges:
        # Step 1: Host discovery
        host_discovery_file = run_nmap_host_discovery(ip_range)
        
        # Step 2: Port scanning
        port_scan_file = run_nmap_port_scan(ip_range)
        
        # Step 3: Generate HTML report
        generate_html_report(port_scan_file)

if __name__ == "__main__":
    main()
