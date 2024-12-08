
import csv
from collections import defaultdict, Counter

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parse the log file and return extracted data."""
    requests_per_ip = defaultdict(int)
    endpoint_counter = Counter()
    failed_logins = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue
            
            # Extract IP address and endpoint
            ip_address = parts[0]
            request_info = parts[5].strip('"')  # e.g., GET, POST
            endpoint = parts[6]  # e.g., /home, /login
            status_code = parts[8]
            
            # Update IP request count
            requests_per_ip[ip_address] += 1
            
            # Update endpoint access count
            endpoint_counter[endpoint] += 1
            
            # Track failed logins
            if status_code == "401":
                failed_logins[ip_address] += 1
                
    return requests_per_ip, endpoint_counter, failed_logins

def save_to_csv(file_name, ip_requests, most_accessed_endpoint, suspicious_ips):
    """Save the analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        writer.writerow([])  # Add a blank row
        
        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        
        writer.writerow([])  # Add a blank row
        
        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # File paths
    log_file = "sample.log"
    output_csv = "log_analysis_results.csv"
    
    # Parse the log file
    requests_per_ip, endpoint_counter, failed_logins = parse_log_file(log_file)
    
    # Find the most accessed endpoint
    most_accessed_endpoint = endpoint_counter.most_common(1)[0]
    
    # Identify suspicious IPs
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    
    # Display the results
    print("IP Address           Request Count")
    for ip, count in sorted(requests_per_ip.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    
    # Save results to CSV
    save_to_csv(output_csv, requests_per_ip, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()
