# backend/operations/siem_connector.py

# System Requirement: Log and monitor all system activities through a centralized 
# SIEM system for threat detection and analysis.

from enum import Enum
import json
import logging
import socket
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Dict, List, Optional, Union
import hashlib
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EventSeverity(Enum):
    """Event severity levels for security events."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

class EventCategory(Enum):
    """Categories of security events to be monitored."""
    AUTHENTICATION = "AUTH"
    ACCESS_CONTROL = "ACCESS"
    DATA_ACCESS = "DATA"
    SYSTEM = "SYSTEM"
    SECURITY = "SECURITY"
    NETWORK = "NETWORK"
    COMPLIANCE = "COMPLIANCE"
    THREAT = "THREAT"

class SIEMConnector:
    def __init__(self, 
                 host: str = "siem.example.com",
                 port: int = 514,
                 app_name: str = "SecurityApp",
                 facility: str = "security",
                 max_queue_size: int = 10000,
                 batch_size: int = 100):
        """
        Initialize the SIEM connector with configuration parameters.
        
        Args:
            host: SIEM server hostname
            port: SIEM server port
            app_name: Application identifier
            facility: Syslog facility
            max_queue_size: Maximum events in queue
            batch_size: Number of events to send in one batch
        """
        self.host = host
        self.port = port
        self.app_name = app_name
        self.facility = facility
        self.batch_size = batch_size
        
        # Initialize event queue
        self.event_queue: Queue = Queue(maxsize=max_queue_size)
        
        # Metrics tracking
        self.metrics = {
            "events_received": 0,
            "events_sent": 0,
            "events_dropped": 0,
            "last_send_time": None,
            "queue_size": 0
        }
        
        # Start background worker
        self.running = True
        self.worker = threading.Thread(target=self._process_queue)
        self.worker.daemon = True
        self.worker.start()

    def log_security_event(self,
                          category: EventCategory,
                          severity: EventSeverity,
                          message: str,
                          source_ip: Optional[str] = None,
                          user_id: Optional[str] = None,
                          details: Optional[Dict] = None) -> bool:
        """
        Log a security event to the SIEM system.
        
        Args:
            category: Event category
            severity: Event severity level
            message: Event description
            source_ip: Source IP address
            user_id: User identifier
            details: Additional event details
            
        Returns:
            bool: True if event was queued successfully
        """
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_id": self._generate_event_id(),
                "category": category.value,
                "severity": severity.value,
                "message": message,
                "source_ip": source_ip,
                "user_id": user_id,
                "app_name": self.app_name,
                "hostname": socket.gethostname(),
                "details": details or {}
            }
            
            if self.event_queue.full():
                logger.warning("Event queue full - dropping event")
                self.metrics["events_dropped"] += 1
                return False
                
            self.event_queue.put(event)
            self.metrics["events_received"] += 1
            self.metrics["queue_size"] = self.event_queue.qsize()
            return True
            
        except Exception as e:
            logger.error(f"Error logging security event: {str(e)}")
            return False

    def _process_queue(self):
        """Process queued events in the background."""
        while self.running:
            try:
                events = []
                # Collect batch of events
                while len(events) < self.batch_size and not self.event_queue.empty():
                    events.append(self.event_queue.get_nowait())
                
                if events:
                    self._send_events(events)
                    
                time.sleep(0.1)  # Prevent tight loop
                    
            except Exception as e:
                logger.error(f"Error processing event queue: {str(e)}")
                time.sleep(1)  # Back off on error

    def _send_events(self, events: List[Dict]):
        """Send events to SIEM server."""
        try:
            # In production, replace with actual SIEM server connection
            # For demonstration, we'll log to console and file
            
            # Format events in CEF format
            for event in events:
                cef_message = self._format_cef_message(event)
                
                # Log to console for demonstration
                logger.info(f"SIEM Event: {cef_message}")
                
                # In production, send to SIEM server:
                # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                #     sock.connect((self.host, self.port))
                #     sock.sendall(cef_message.encode('utf-8'))
                
                self.metrics["events_sent"] += 1
                
            self.metrics["last_send_time"] = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error sending events to SIEM: {str(e)}")
            # Re-queue events for retry in production
            
    def _format_cef_message(self, event: Dict) -> str:
        """Format event in Common Event Format (CEF)."""
        cef_version = 0
        device_vendor = "SecurityApp"
        device_product = self.app_name
        device_version = "1.0"
        signature_id = f"{event['category']}_{event['severity']}"
        name = event['message']
        severity = event['severity']
        
        # Basic CEF format
        header = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}"
        
        # Add extension fields
        extensions = [
            f"eventId={event['event_id']}",
            f"deviceTime={event['timestamp']}",
            f"src={event.get('source_ip', 'N/A')}",
            f"suser={event.get('user_id', 'N/A')}",
            f"dhost={event['hostname']}"
        ]
        
        # Add custom details
        for key, value in event.get('details', {}).items():
            extensions.append(f"{key}={value}")
            
        return f"{header}|{' '.join(extensions)}"

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        unique = f"{time.time()}{os.getpid()}{threading.get_ident()}"
        return hashlib.sha256(unique.encode()).hexdigest()[:16]

    def get_metrics(self) -> Dict:
        """Get current metrics about SIEM operations."""
        self.metrics["queue_size"] = self.event_queue.qsize()
        return self.metrics

    def shutdown(self):
        """Gracefully shutdown the SIEM connector."""
        self.running = False
        self.worker.join(timeout=5.0)
        
        # Process remaining events
        while not self.event_queue.empty():
            events = []
            while len(events) < self.batch_size and not self.event_queue.empty():
                events.append(self.event_queue.get_nowait())
            if events:
                self._send_events(events)


def main():
    """Example usage of the SIEM connector."""
    # Initialize SIEM connector
    siem = SIEMConnector(
        host="siem.example.com",
        port=514,
        app_name="SecurityDemo"
    )
    
    try:
        # Example 1: Log successful login
        siem.log_security_event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.INFO,
            message="User login successful",
            source_ip="192.168.1.100",
            user_id="user123",
            details={
                "auth_method": "2FA",
                "location": "Sydney"
            }
        )
        
        # Example 2: Log suspicious activity
        siem.log_security_event(
            category=EventCategory.SECURITY,
            severity=EventSeverity.HIGH,
            message="Multiple failed login attempts detected",
            source_ip="10.0.0.5",
            details={
                "attempt_count": 5,
                "time_window": "5 minutes"
            }
        )
        
        # Example 3: Log compliance check
        siem.log_security_event(
            category=EventCategory.COMPLIANCE,
            severity=EventSeverity.MEDIUM,
            message="Weekly security audit completed",
            details={
                "audit_id": "SEC-AUDIT-2023-001",
                "findings": "3 minor issues detected"
            }
        )
        
        # Wait a bit for events to be processed
        time.sleep(2)
        
        # Print metrics
        print("\nSIEM Metrics:")
        print(json.dumps(siem.get_metrics(), indent=2))
        
    finally:
        # Ensure proper shutdown
        siem.shutdown()


if __name__ == "__main__":
    main()
