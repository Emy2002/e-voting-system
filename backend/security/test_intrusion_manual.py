from backend import app
from backend.security.intrusion_detection import IntrusionDetection
from datetime import datetime, timedelta
import time

def test_intrusion_detection():
    # Initialize intrusion detection with shorter windows for testing
    intrusion = IntrusionDetection(
        max_attempts=5,
        window_minutes=5,
        lockout_minutes=1,
        base_delay_seconds=1,
        max_delay_seconds=10
    )
    test_ip = "192.168.1.100"
    
    print("\n=== Testing Intrusion Detection System ===\n")
    
    # Test 1: Single failed attempt
    print("Test 1: Single Failed Attempt")
    print(f"Recording failed attempt for IP: {test_ip}")
    delay = intrusion.record_failed_attempt(test_ip)
    print(f"Delay after 1 attempt: {delay} seconds")
    print(f"Current attempts for IP: {len(intrusion.failed_logins[test_ip])}")
    print("✓ Test 1 completed\n")
    
    # Test 2: Multiple failed attempts (trigger lockout)
    print("Test 2: Multiple Failed Attempts")
    print(f"Recording multiple failed attempts for IP: {test_ip}")
    for i in range(4):  # Total 5 attempts with the one above
        delay = intrusion.record_failed_attempt(test_ip)
        print(f"Attempt {i+2} recorded - Delay: {delay} seconds")
        if delay > 0:
            print(f"IP is now locked out for {delay} seconds")
    
    print(f"Current attempts for IP: {len(intrusion.failed_logins[test_ip])}")
    print("✓ Test 2 completed\n")
    
    # Test 3: Lockout expiration
    print("Test 3: Lockout Expiration")
    print("Waiting for lockout to expire...")
    time.sleep(65)  # Wait for lockout to expire
    delay = intrusion.record_failed_attempt(test_ip)
    print(f"Delay after lockout expired: {delay} seconds")
    print("✓ Test 3 completed\n")
    
    # Test 4: Multiple IPs
    print("Test 4: Multiple IPs")
    test_ips = ["192.168.1.101", "192.168.1.102", "192.168.1.103"]
    for ip in test_ips:
        print(f"\nTesting IP: {ip}")
        # Record 3 attempts for each IP
        for i in range(3):
            delay = intrusion.record_failed_attempt(ip)
            print(f"Recorded attempt {i+1} for {ip} - Delay: {delay} seconds")
    print("✓ Test 4 completed\n")
    
    # Test 5: Progressive delay
    print("Test 5: Progressive Delay Test")
    test_ip_delay = "192.168.1.104"
    print(f"Testing progressive delay for IP: {test_ip_delay}")
    for i in range(4):
        delay = intrusion.record_failed_attempt(test_ip_delay)
        print(f"Attempt {i+1} - Delay: {delay} seconds")
        if delay > 0 and delay < 60:  # If it's a throttle delay (not lockout)
            print(f"Waiting for delay ({delay}s)...")
            time.sleep(delay)
    print("✓ Test 5 completed\n")
    
    # Print final statistics
    print("=== Final Statistics ===")
    print(f"Total IPs tracked: {len(intrusion.failed_logins)}")
    for ip, attempts in intrusion.failed_logins.items():
        print(f"IP: {ip}")
        print(f"  Attempts: {len(attempts)}")
        print(f"  Next allowed: {intrusion.next_allowed.get(ip, 'Now')}")
        print(f"  Locked until: {intrusion.locks.get(ip, 'Not locked')}")

if __name__ == '__main__':
    with app.app_context():
        test_intrusion_detection()