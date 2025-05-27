
# DNS Exfiltration Detection Using Python and Pandas

This project is a playground for educational purposes. It demonstrates how to detect **DNS-based data exfiltration** using traffic analytics techniques applied to real PCAP data. It includes modular scripts and a Jupyter Notebook that performs parsing, enrichment, statistical analysis, and threat hunting.

## Project Structure

```
dns-exfiltration-detection/
├── Notebooks/
│   └── dns_exfiltration_github.ipynb     # Main analysis notebook
├── Scripts/
│   ├── pcap_parser.py                    # Scapy-based PCAP parser (used externally)
│   ├── dns_utils.py                      # Feature engineering helpers (entropy, subdomains)
│   └── beacon_analysis.py                # Beaconing detection helpers
├── parsed_output/                        # Stores parsed JSON logs
│   └── dns_traffic.json
├── images/                               # Visual charts (optional)
│   └── subdomain_cardinality_pie_chart.png
├── README.md
├── .gitignore
├── requirements.txt                      # For running the notebook
└── requirements-scripts.txt              # For running helper scripts like the PCAP parser
```

## Getting Started

1. Clone the repo:
```bash
git clone https://github.com/hmaosa/dns-exfiltration-analysis.git
cd dns-exfiltration-analysis
```

2. Install notebook dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install script dependencies if running `pcap_parser.py`:
```bash
pip install -r requirements-scripts.txt
```

4. Launch the notebook:
```bash
cd Notebooks
jupyter lab dns_exfiltration_github.ipynb
```

## What the Project Does

- Parses DNS traffic from JSON-serialized PCAP files
- Computes query name entropy and subdomain cardinality
- Analyzes timing patterns and potential beaconing behavior
- Visualizes suspicious patterns in DNS traffic
- Highlights exfiltration indicators (e.g. high cardinality + rcode=0 + no answers)

## Output Highlights

- Inter-request interval histogram
- Mean vs Std Dev scatter plot for beaconing
- Subdomain cardinality pie chart
- Final threat hunting judgment narrative

## Dataset

- **Source**: [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html)
- **Used**: Parsed JSON version of DNS traffic from PCAP

## Author

Herbert Maosa  
Cybersecurity Consultant | PhD | CISSP | OSCP  
[LinkedIn](https://www.linkedin.com/in/herbert-maosa-993518120/)

---

> This project is for research and educational purposes only. DNS activity should always be interpreted in context with host and threat intelligence data.
