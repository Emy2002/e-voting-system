# backend/security/geolocation.py

# SR-09: Stub for geolocation access control - implement IP to geo lookup with blocking rules
def is_access_allowed(ip_address, allowed_regions=None):
    # Example: Use geoip2 or external API to get location
    # Return true if IP is in allowed_regions else false
    # For demo, allow all
    return True
