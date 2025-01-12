import requests

# Replace with your own VirusTotal API key
API_KEY = 'your_virustotal_api_key'  # Be sure to update this
BASE_URL = 'https://www.virustotal.com/api/v3/urls/'

# Function to encode URL for VirusTotal
def encode_url(url):
    return requests.utils.quote(url)

# Function to check if the URL is suspicious
def check_url(url):
    headers = {
        'x-apikey': API_KEY
    }

    # Encode URL before sending
    encoded_url = encode_url(url)

    # Send the request to VirusTotal API
    response = requests.get(BASE_URL + encoded_url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"The URL '{url}' is suspicious and flagged as malicious.")
        else:
            print(f"The URL '{url}' seems safe.")
    else:
        print(f"Error: {response.status_code} - Unable to analyze the URL.")

if __name__ == "__main__":
    # Test links
    links_to_check = [
        "http://example.com",  # Replace with links you want to test
        "https://malicious-site.com"
    ]

    for link in links_to_check:
        check_url(link)
