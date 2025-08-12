from scapy.all import sniff, IP, TCP
from collections import defaultdict
import requests

# Configuration
MALICIOUS_IPS = {"192.168.1.100"}  # Local malicious IP list
SUSPICIOUS_PORTS = {4444, 31337}   # Local suspicious ports
ANOMALY_THRESHOLD = 10             # Local anomaly threshold
THREAT_API_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY = "884abe60341dac35e4d4836e11cac34be20d64a14e1b701263e13e53a0cd0a22f7439473ac4d5ae0"

class NIDS:
    def __init__(self):
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
    
    def check_api(self, ip):
        """Check IP reputation using external API"""
        try:
            headers = {
                'Key': '884abe60341dac35e4d4836e11cac34be20d64a14e1b701263e13e53a0cd0a22f7439473ac4d5ae0',
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if data.get("data", {}).get("abuseConfidenceScore", 0) > 50:
                    return True
        except Exception as e:
            print(f"[ERROR] API check failed: {e}")
        return False

    def analyze_packet(self, packet):
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # Flags
        local_detected = False
        api_verified = False

        # Local Detection Rules
        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            print(f"⚠️ [LOCAL ANOMALY] Malicious IP detected: {src_ip} -> {dst_ip}")
            local_detected = True

        if src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS:
            print(f"⚠️ [LOCAL ANOMALY] Suspicious port activity: {src_port} -> {dst_port}")
            local_detected = True

        self.ip_counts[src_ip] += 1
        if self.ip_counts[src_ip] == ANOMALY_THRESHOLD:
            print(f"⚠️ [LOCAL ANOMALY] High traffic from IP: {src_ip}")
            local_detected = True

        if dst_port:
            self.port_counts[dst_port] += 1
            if self.port_counts[dst_port] == ANOMALY_THRESHOLD:
                print(f"⚠️ [LOCAL ANOMALY] High traffic on port: {dst_port}")
                local_detected = True

        # API Verification (Only if local detection triggered OR check all)
        if local_detected:
            if self.check_api(src_ip) or self.check_api(dst_ip):
                api_verified = True
                print(f"✅ [API VERIFIED] Threat confirmed by Threat Intelligence API: {src_ip} -> {dst_ip}")

        # High Confidence Alert (Both Local + API)
        if local_detected and api_verified:
            print(f"🚨 [HONORABLE ALERT] Verified malicious activity: {src_ip} -> {dst_ip}")

def start_nids():
    print("🚀 NIDS Started")
    print("Press Ctrl+C to stop\n")
    nids = NIDS()
    sniff(prn=nids.analyze_packet, store=0)

if __name__ == "__main__":
    start_nids()
