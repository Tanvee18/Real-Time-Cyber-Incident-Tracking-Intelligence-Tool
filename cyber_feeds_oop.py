import requests
import json
import zipfile
import io
import feedparser
import mysql.connector
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any


class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self, host: str = "localhost", user: str = "root", 
                 password: str = "Tanvee@18", database: str = "project"):
        self.connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        self.cursor = self.connection.cursor()
    
    def close(self):
        """Close database connection"""
        self.cursor.close()
        self.connection.close()
    
    def execute_query(self, query: str, params: tuple = None):
        """Execute a database query"""
        if params:
            self.cursor.execute(query, params)
        else:
            self.cursor.execute(query)
        self.connection.commit()
        return self.cursor.fetchall()
    
    def insert_raw_feed(self, source: str, data: str):
        """Insert raw feed data into database"""
        query = "INSERT INTO raw_feeds (source, data, timestamp) VALUES (%s, %s, NOW())"
        self.execute_query(query, (source, data))
    
    def insert_incident(self, incident: 'Incident'):
        """Insert incident into database"""
        query = """INSERT INTO incidents (type, sector, severity, details, timestamp, category, analysis) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s)"""
        params = (incident.type, incident.sector, incident.severity, 
                 incident.details, incident.timestamp, incident.category, incident.analysis)
        self.execute_query(query, params)
    
    def insert_alert(self, incident_id: int, alert_type: str, recipient: str):
        """Insert alert into database"""
        query = "INSERT INTO alert (incident_id, alert_type, recipient) VALUES (%s, %s, %s)"
        self.execute_query(query, (incident_id, alert_type, recipient))


class Incident:
    """Represents a cyber security incident"""
    
    def __init__(self, incident_type: str = "Unknown", sector: str = "Unknown", 
                 severity: str = "low", details: str = "", category: str = "Uncategorized",
                 analysis: str = "No specific match found."):
        self.type = incident_type
        self.sector = sector
        self.severity = severity
        self.details = details
        self.category = category
        self.analysis = analysis
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def __str__(self):
        return f"Incident({self.type}, {self.severity}, {self.sector})"
    
    def to_dict(self):
        """Convert incident to dictionary"""
        return {
            'type': self.type,
            'sector': self.sector,
            'severity': self.severity,
            'details': self.details,
            'category': self.category,
            'analysis': self.analysis,
            'timestamp': self.timestamp
        }


class DataSource(ABC):
    """Abstract base class for data sources"""
    
    def __init__(self, url: str, source_name: str):
        self.url = url
        self.source_name = source_name
    
    @abstractmethod
    def fetch_data(self) -> Dict[str, Any]:
        """Fetch data from the source"""
        pass


class AbuseChDataSource(DataSource):
    """Data source for Abuse.ch malware feeds"""
    
    def fetch_data(self) -> Dict[str, Any]:
        try:
            resp = requests.get(self.url, timeout=10)
            resp.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                with z.open(z.namelist()[0]) as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        data = data[:5]  # first 5 items
                    return {"type": "json", "data": data}
        except Exception as e:
            return {"error": str(e)}


class RSSDataSource(DataSource):
    """Data source for RSS feeds"""
    
    def fetch_data(self) -> Dict[str, Any]:
        try:
            feed = feedparser.parse(self.url)
            return {"type": "rss", "entries": [{"title": e.title, "link": e.link} 
                                             for e in feed.entries[:5]]}
        except Exception as e:
            return {"error": str(e)}


class JSONDataSource(DataSource):
    """Data source for JSON feeds"""
    
    def fetch_data(self) -> Dict[str, Any]:
        try:
            resp = requests.get(self.url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                data = data[:5]
            return {"type": "json", "data": data}
        except Exception as e:
            return {"error": str(e)}


class TextDataSource(DataSource):
    """Data source for text feeds"""
    
    def fetch_data(self) -> Dict[str, Any]:
        try:
            resp = requests.get(self.url, timeout=10)
            resp.raise_for_status()
            return {"type": "text", "lines": resp.text.splitlines()[:10]}
        except Exception as e:
            return {"error": str(e)}


class DataSourceManager:
    """Manages multiple data sources and their fetching"""
    
    def __init__(self):
        self.sources = {}
        self._setup_default_sources()
    
    def _setup_default_sources(self):
        """Setup default data sources"""
        self.sources = {
            "abuse_ch_malware": AbuseChDataSource(
                "https://urlhaus.abuse.ch/downloads/json/", "Abuse.ch Malware"
            ),
            "cyber_blog": RSSDataSource(
                "https://krebsonsecurity.com/feed/", "Krebs on Security"
            ),
            "cert_in": RSSDataSource(
                "https://www.cert-in.org.in/RSSThreats.xml", "CERT-In India"
            ),
            "spamhaus_drop": TextDataSource(
                "https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP"
            )
        }
    
    def add_source(self, name: str, source: DataSource):
        """Add a new data source"""
        self.sources[name] = source
    
    def fetch_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """Fetch data from all sources"""
        results = {}
        for name, source in self.sources.items():
            print(f"\n--- Fetching {name} ---")
            data = source.fetch_data()
            print(json.dumps(data, indent=2))
            results[name] = data
        return results


class SectorCategorizer:
    """Categorizes incidents by sector"""
    
    def __init__(self):
        self.sector_keywords = {
            "Financial": ["bank", "financial", "payment", "credit", "transaction", "fintech"],
            "Healthcare": ["health", "medical", "hospital", "patient", "pharma", "healthcare"],
            "Government": ["government", "gov", "public", "ministry", "department", "official"],
            "Education": ["education", "school", "university", "college", "student", "academic"],
            "Technology": ["tech", "software", "hardware", "it", "cyber", "digital"],
            "Energy": ["energy", "power", "electric", "oil", "gas", "utility"],
            "Transportation": ["transport", "logistics", "shipping", "aviation", "railway"],
            "Retail": ["retail", "commerce", "shopping", "ecommerce", "store", "marketplace"]
        }
    
    def categorize_sector(self, details: str) -> str:
        """Categorize incident by sector based on details"""
        details_lower = details.lower()
        
        for sector, keywords in self.sector_keywords.items():
            if any(keyword in details_lower for keyword in keywords):
                return sector
        
        return "Unknown"


class IncidentAnalyzer:
    """Analyzes and categorizes cyber incidents"""
    
    def __init__(self):
        self.sector_categorizer = SectorCategorizer()
        self.analysis_keywords = {
            "Malware": {
                "keywords": ["malware", "trojan", "ransomware", "botnet", "virus", "worm"],
                "severity": "high",
                "analysis": "This incident is related to malware activity."
            },
            "Phishing": {
                "keywords": ["phish", "credential", "login", "spoof", "fake", "scam"],
                "severity": "medium",
                "analysis": "This incident seems to be a phishing attempt."
            },
            "Spam/Blacklist": {
                "keywords": ["spam", "blacklist", "drop", "spamming", "blocklist"],
                "severity": "medium",
                "analysis": "This incident is related to spam or blacklist data."
            },
            "Vulnerability": {
                "keywords": ["cve", "exploit", "vulnerability", "patch", "security hole"],
                "severity": "critical",
                "analysis": "This incident reports a security vulnerability."
            },
            "DDoS": {
                "keywords": ["ddos", "dos", "denial", "flood", "attack"],
                "severity": "high",
                "analysis": "This incident involves a denial of service attack."
            },
            "Data Breach": {
                "keywords": ["breach", "leak", "exposed", "stolen", "compromised"],
                "severity": "critical",
                "analysis": "This incident involves a data breach or leak."
            }
        }
    
    def analyze_incident(self, details: str) -> tuple[str, str, str]:
        """Analyze incident and return (category, severity, analysis)"""
        details_lower = details.lower()
        
        for category, info in self.analysis_keywords.items():
            if any(keyword in details_lower for keyword in info["keywords"]):
                return category, info["severity"], info["analysis"]
        
        return "Uncategorized", "low", "No specific match found."
    
    def create_incident_from_data(self, data: Dict[str, Any], source_type: str) -> List[Incident]:
        """Create incidents from fetched data"""
        incidents = []
        
        if "data" in data and isinstance(data["data"], list):
            # JSON data
            for item in data["data"]:
                if isinstance(item, dict):
                    details = str(item)
                    category, severity, analysis = self.analyze_incident(details)
                    sector = self.sector_categorizer.categorize_sector(details)
                    
                    incident = Incident(
                        incident_type=item.get("type", source_type),
                        sector=sector,
                        severity=severity,
                        details=details,
                        category=category,
                        analysis=analysis
                    )
                    incidents.append(incident)
        
        elif "entries" in data:
            # RSS data
            for entry in data["entries"]:
                details = f"{entry.get('title', '')} - {entry.get('link', '')}"
                category, severity, analysis = self.analyze_incident(details)
                sector = self.sector_categorizer.categorize_sector(details)
                
                incident = Incident(
                    incident_type="RSS",
                    sector=sector,
                    severity=severity,
                    details=details,
                    category=category,
                    analysis=analysis
                )
                incidents.append(incident)
        
        elif "lines" in data:
            # Text data
            for line in data["lines"]:
                category, severity, analysis = self.analyze_incident(line)
                sector = self.sector_categorizer.categorize_sector(line)
                
                incident = Incident(
                    incident_type="Text",
                    sector=sector,
                    severity=severity,
                    details=line,
                    category=category,
                    analysis=analysis
                )
                incidents.append(incident)
        
        return incidents


class AlertGenerator:
    """Generates alerts for incidents"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.alert_thresholds = {
            "critical": ["securityteam@example.com", "management@example.com"],
            "high": ["securityteam@example.com"],
            "medium": ["securityteam@example.com"]
        }
    
    def generate_alert(self, incident: Incident, incident_id: int):
        """Generate alert for an incident"""
        if incident.severity.lower() in self.alert_thresholds:
            recipients = self.alert_thresholds[incident.severity.lower()]
            for recipient in recipients:
                self.db_manager.insert_alert(incident_id, "Email", recipient)
    
    def generate_alerts_for_incidents(self, incidents: List[Incident]):
        """Generate alerts for a list of incidents"""
        for i, incident in enumerate(incidents, 1):
            if incident.severity.lower() in ["medium", "high", "critical"]:
                self.generate_alert(incident, i)


class CyberFeedManager:
    """Main orchestrator class for the cyber feed system"""
    
    def __init__(self, db_config: Dict[str, str] = None):
        self.db_manager = DatabaseManager(**(db_config or {}))
        self.data_source_manager = DataSourceManager()
        self.incident_analyzer = IncidentAnalyzer()
        self.alert_generator = AlertGenerator(self.db_manager)
    
    def process_feeds(self):
        """Main method to process all feeds"""
        print("Starting cyber feed processing...")
        
        # Fetch data from all sources
        all_feeds_data = self.data_source_manager.fetch_all_sources()
        
        # Store raw feeds and process incidents
        all_incidents = []
        for source_name, data in all_feeds_data.items():
            # Store raw feed
            self.db_manager.insert_raw_feed(source_name, json.dumps(data))
            
            # Create incidents from data
            incidents = self.incident_analyzer.create_incident_from_data(data, source_name)
            all_incidents.extend(incidents)
        
        # Store incidents in database
        for incident in all_incidents:
            self.db_manager.insert_incident(incident)
        
        # Generate alerts
        self.alert_generator.generate_alerts_for_incidents(all_incidents)
        
        print(f"\nProcessing complete! Processed {len(all_incidents)} incidents.")
        return all_incidents
    
    def get_incidents_by_severity(self, severity: str) -> List[Incident]:
        """Get incidents by severity level"""
        query = "SELECT * FROM incidents WHERE severity = %s"
        results = self.db_manager.execute_query(query, (severity,))
        
        incidents = []
        for row in results:
            incident = Incident(
                incident_type=row[1],
                sector=row[2],
                severity=row[3],
                details=row[4],
                category=row[5] if len(row) > 5 else "Unknown",
                analysis=row[6] if len(row) > 6 else "No analysis"
            )
            incident.timestamp = row[5] if len(row) > 5 else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            incidents.append(incident)
        
        return incidents
    
    def get_incidents_by_sector(self, sector: str) -> List[Incident]:
        """Get incidents by sector"""
        query = "SELECT * FROM incidents WHERE sector = %s"
        results = self.db_manager.execute_query(query, (sector,))
        
        incidents = []
        for row in results:
            incident = Incident(
                incident_type=row[1],
                sector=row[2],
                severity=row[3],
                details=row[4],
                category=row[5] if len(row) > 5 else "Unknown",
                analysis=row[6] if len(row) > 6 else "No analysis"
            )
            incident.timestamp = row[5] if len(row) > 5 else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            incidents.append(incident)
        
        return incidents
    
    def close(self):
        """Close database connection"""
        self.db_manager.close()


def main():
    """Main function to run the cyber feed system"""
    try:
        # Initialize the cyber feed manager
        cyber_manager = CyberFeedManager()
        
        # Process all feeds
        incidents = cyber_manager.process_feeds()
        
        # Display some statistics
        print(f"\n=== Processing Statistics ===")
        print(f"Total incidents processed: {len(incidents)}")
        
        # Group by severity
        severity_counts = {}
        for incident in incidents:
            severity_counts[incident.severity] = severity_counts.get(incident.severity, 0) + 1
        
        print(f"\nSeverity breakdown:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        # Group by sector
        sector_counts = {}
        for incident in incidents:
            sector_counts[incident.sector] = sector_counts.get(incident.sector, 0) + 1
        
        print(f"\nSector breakdown:")
        for sector, count in sector_counts.items():
            print(f"  {sector}: {count}")
        
        # Group by category
        category_counts = {}
        for incident in incidents:
            category_counts[incident.category] = category_counts.get(incident.category, 0) + 1
        
        print(f"\nCategory breakdown:")
        for category, count in category_counts.items():
            print(f"  {category}: {count}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'cyber_manager' in locals():
            cyber_manager.close()


if __name__ == "__main__":
    main()
