package license;

public enum EventType {
	LicenseChange("license_change"),
    ConnectionError("connection_error"),
    LicenseExpiring("license_expiring");
    
    private final String eventType;
    
    private EventType(String eventType) {
    	this.eventType = eventType;
    }
	
    private String getEventType() {
    	return eventType;
    }
}