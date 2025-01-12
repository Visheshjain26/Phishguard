# Phishing Link Detection Tool

## Description
This Python tool checks whether a given URL is malicious or suspicious by integrating with the **VirusTotal API**. The tool sends URLs to VirusTotal to analyze whether they are flagged as malicious by antivirus engines and other security vendors.

## Features
- Check suspicious URLs using VirusTotal API.
- Provides real-time phishing detection results.
- Outputs whether a URL is safe or flagged as malicious.

## Prerequisites
1. Python 3.x installed on your machine.
2. A **VirusTotal API key** (free tier available).

## Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/your_username/phishing-link-detector.git
    cd phishing-link-detector
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Replace `'your_virustotal_api_key'` in the `main.py` file with your actual API key from VirusTotal.

4. Run the script:
    ```bash
    python main.py
    ```

## License
MIT License

