#!/usr/bin/env python3
"""
Test script for the OOP cyber feeds system
"""

from cyber_feeds_oop import (
    CyberFeedManager, 
    Incident, 
    DataSourceManager, 
    IncidentAnalyzer, 
    SectorCategorizer,
    AlertGenerator,
    DatabaseManager
)

def test_incident_creation():
    """Test incident creation"""
    print("Testing Incident creation...")
    incident = Incident(
        incident_type="Malware",
        sector="Financial",
        severity="high",
        details="Ransomware attack on bank systems",
        category="Malware",
        analysis="Critical malware incident"
    )
    
    print(f"Created incident: {incident}")
    print(f"Incident details: {incident.to_dict()}")
    print("✓ Incident creation test passed\n")

def test_sector_categorizer():
    """Test sector categorization"""
    print("Testing SectorCategorizer...")
    categorizer = SectorCategorizer()
    
    test_cases = [
        ("Bank account compromised", "Financial"),
        ("Hospital data breach", "Healthcare"),
        ("Government website hacked", "Government"),
        ("University system down", "Education"),
        ("Unknown attack", "Unknown")
    ]
    
    for details, expected in test_cases:
        result = categorizer.categorize_sector(details)
        status = "✓" if result == expected else "✗"
        print(f"{status} '{details}' -> {result} (expected: {expected})")
    
    print("Sector categorization test completed\n")

def test_incident_analyzer():
    """Test incident analysis"""
    print("Testing IncidentAnalyzer...")
    analyzer = IncidentAnalyzer()
    
    test_cases = [
        ("Ransomware attack detected", "Malware", "high"),
        ("Phishing email campaign", "Phishing", "medium"),
        ("CVE-2024-1234 vulnerability", "Vulnerability", "critical"),
        ("Spam email detected", "Spam/Blacklist", "medium"),
        ("DDoS attack on server", "DDoS", "high"),
        ("Data breach reported", "Data Breach", "critical"),
        ("Unknown security event", "Uncategorized", "low")
    ]
    
    for details, expected_category, expected_severity in test_cases:
        category, severity, analysis = analyzer.analyze_incident(details)
        cat_status = "✓" if category == expected_category else "✗"
        sev_status = "✓" if severity == expected_severity else "✗"
        print(f"{cat_status}{sev_status} '{details}' -> {category}/{severity} (expected: {expected_category}/{expected_severity})")
    
    print("Incident analysis test completed\n")

def test_data_source_manager():
    """Test data source manager"""
    print("Testing DataSourceManager...")
    manager = DataSourceManager()
    
    print(f"Available sources: {list(manager.sources.keys())}")
    
    # Test fetching from one source (without actually making HTTP requests)
    print("Testing source structure...")
    for name, source in manager.sources.items():
        print(f"  {name}: {type(source).__name__} -> {source.url}")
    
    print("✓ DataSourceManager test passed\n")

def test_cyber_feed_manager_initialization():
    """Test cyber feed manager initialization"""
    print("Testing CyberFeedManager initialization...")
    
    try:
        # Test with mock database config to avoid actual DB connection
        manager = CyberFeedManager({
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test'
        })
        
        print("✓ CyberFeedManager initialized successfully")
        print(f"  - Data sources: {len(manager.data_source_manager.sources)}")
        print(f"  - Incident analyzer: {type(manager.incident_analyzer).__name__}")
        print(f"  - Alert generator: {type(manager.alert_generator).__name__}")
        
    except Exception as e:
        print(f"✗ CyberFeedManager initialization failed: {e}")
    
    print("CyberFeedManager test completed\n")

def main():
    """Run all tests"""
    print("=" * 50)
    print("CYBER FEEDS OOP SYSTEM - TEST SUITE")
    print("=" * 50)
    
    test_incident_creation()
    test_sector_categorizer()
    test_incident_analyzer()
    test_data_source_manager()
    test_cyber_feed_manager_initialization()
    
    print("=" * 50)
    print("ALL TESTS COMPLETED")
    print("=" * 50)

if __name__ == "__main__":
    main()
