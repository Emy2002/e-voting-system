# backend/security/geolocation.py

# System Requirement: Enforce geolocation-based access control, restricting access
# to diplomatic missions or allowed Australian regions only.

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import json
from functools import lru_cache
import logging
from math import radians, sin, cos, sqrt, atan2

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class GeoLocation:
    latitude: float
    longitude: float
    country_code: str
    region: str
    city: str
    is_diplomatic_mission: bool = False

class GeolocationVerifier:
    def __init__(self):
        """
        Initialize the GeolocationVerifier with Australian regions and diplomatic missions.
        """
        # Australian regions bounding boxes (approximate)
        self.australian_regions = {
            "NSW": {"min_lat": -37.5, "max_lat": -28.0, "min_long": 141.0, "max_long": 153.5},
            "VIC": {"min_lat": -39.2, "max_lat": -34.0, "min_long": 141.0, "max_long": 150.0},
            "QLD": {"min_lat": -29.0, "max_lat": -10.0, "min_long": 138.0, "max_long": 154.0},
            "WA":  {"min_lat": -35.5, "max_lat": -14.0, "min_long": 113.0, "max_long": 129.0},
            "SA":  {"min_lat": -38.0, "max_lat": -26.0, "min_long": 129.0, "max_long": 141.0},
            "TAS": {"min_lat": -43.7, "max_lat": -39.5, "min_long": 143.5, "max_long": 148.5},
            "NT":  {"min_lat": -26.0, "max_lat": -11.0, "min_long": 129.0, "max_long": 138.0},
            "ACT": {"min_lat": -35.9, "max_lat": -35.1, "min_long": 148.8, "max_long": 149.4}
        }

        # List of diplomatic missions (example coordinates)
        self.diplomatic_missions = [
            {
                "name": "Australian Embassy Example",
                "location": GeoLocation(-35.3075, 149.1244, "AU", "ACT", "Canberra", True),
                "radius_km": 1.0
            }
            # Add more diplomatic missions as needed
        ]

        # Cache for IP geolocation results
        self.geolocation_cache = {}
        self.cache_ttl = 3600  # 1 hour

        # Rate limiting settings
        self.max_requests_per_hour = 100
        self.request_tracking = {}

    def is_access_allowed(self, ip_address: str, allowed_regions: Optional[List[str]] = None) -> Tuple[bool, str]:
        """
        Verify if the given IP address is within allowed Australian regions or diplomatic missions.
        
        Args:
            ip_address: The IP address to verify
            allowed_regions: Optional list of specific allowed regions (if None, all Australian regions are allowed)
            
        Returns:
            Tuple[bool, str]: (is_allowed, reason)
        """
        try:
            # Validate IP address format
            ipaddress.ip_address(ip_address)
            
            # Check rate limiting
            if not self._check_rate_limit(ip_address):
                return False, "Rate limit exceeded"

            # Get geolocation data
            location = self._get_geolocation(ip_address)
            if not location:
                return False, "Could not determine location"

            # Check if in diplomatic mission
            if self._is_in_diplomatic_mission(location):
                return True, "Access granted - Diplomatic mission"

            # Check if in allowed Australian region
            if location.country_code == "AU":
                if self._is_in_allowed_region(location, allowed_regions):
                    return True, f"Access granted - Australian region ({location.region})"
                return False, "Access denied - Not in allowed Australian region"

            return False, f"Access denied - Location not in Australia ({location.country_code})"

        except ValueError:
            return False, "Invalid IP address format"
        except Exception as e:
            logger.error(f"Error verifying location: {str(e)}")
            return False, "Error processing location verification"

    def _get_geolocation(self, ip_address: str) -> Optional[GeoLocation]:
        """
        Get geolocation data for an IP address (mock implementation for testing).
        """
        # Mock data for testing
        mock_locations = {
            "203.2.218.214": GeoLocation(
                latitude=-33.8688,
                longitude=151.2093,
                country_code="AU",
                region="NSW",
                city="Sydney",
                is_diplomatic_mission=False
            ),
            "172.217.167.78": GeoLocation(
                latitude=37.4192,
                longitude=-122.0574,
                country_code="US",
                region="CA",
                city="Mountain View",
                is_diplomatic_mission=False
            )
        }
        
        return mock_locations.get(ip_address)

    def _is_in_allowed_region(self, location: GeoLocation, allowed_regions: Optional[List[str]] = None) -> bool:
        """Check if the location is within allowed Australian regions."""
        if location.country_code != "AU":
            return False

        for region, bounds in self.australian_regions.items():
            if allowed_regions and region not in allowed_regions:
                continue
                
            if (bounds["min_lat"] <= location.latitude <= bounds["max_lat"] and
                bounds["min_long"] <= location.longitude <= bounds["max_long"]):
                return True
        return False

    def _is_in_diplomatic_mission(self, location: GeoLocation) -> bool:
        """Check if the location is within any diplomatic mission area."""
        for mission in self.diplomatic_missions:
            mission_loc = mission["location"]
            distance = self._calculate_distance(
                location.latitude, location.longitude,
                mission_loc.latitude, mission_loc.longitude
            )
            if distance <= mission["radius_km"]:
                return True
        return False

    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in kilometers using the Haversine formula."""
        R = 6371  # Earth's radius in kilometers

        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c

    def _check_rate_limit(self, ip_address: str) -> bool:
        """Check if the IP has exceeded the rate limit."""
        current_time = datetime.now()
        if ip_address not in self.request_tracking:
            self.request_tracking[ip_address] = []

        # Remove requests older than 1 hour
        self.request_tracking[ip_address] = [
            timestamp for timestamp in self.request_tracking[ip_address]
            if (current_time - timestamp).seconds < 3600
        ]

        # Check if under limit
        if len(self.request_tracking[ip_address]) >= self.max_requests_per_hour:
            return False

        # Add current request
        self.request_tracking[ip_address].append(current_time)
        return True


def main():
    """Example usage of the GeolocationVerifier."""
    verifier = GeolocationVerifier()

    # Test cases
    test_cases = [
        ("203.2.218.214", None),  # Australian IP, all regions allowed
        ("203.2.218.214", ["NSW", "VIC"]),  # Australian IP, specific regions
        "172.217.167.78",  # Non-Australian IP
        "invalid_ip",  # Invalid IP format
    ]

    for test in test_cases:
        if isinstance(test, tuple):
            ip, regions = test
            allowed, reason = verifier.is_access_allowed(ip, regions)
            print(f"\nIP: {ip} (Allowed regions: {regions})")
        else:
            ip = test
            allowed, reason = verifier.is_access_allowed(ip)
            print(f"\nIP: {ip}")
        
        print(f"Allowed: {allowed}")
        print(f"Reason: {reason}")


if __name__ == "__main__":
    main()
