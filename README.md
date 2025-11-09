# 🛡️ Cyber Incident Tracking Dashboard

A real-time cyber incident tracking and intelligence tool that aggregates and analyzes cyber threats specifically affecting Indian cyberspace.

## 🚀 Features

- **Real-time Data Collection**: Fetches data from multiple cybersecurity sources
- **Incident Analysis & Categorization**: Automatically categorizes incidents by severity, sector, and type
- **Interactive Dashboard**: Modern web interface with filtering, search, and statistics
- **Alert System**: Generates alerts for high-priority incidents
- **Database Integration**: MySQL database for data storage and management

## 📊 Data Sources

- **Abuse.ch Malware**: Malware threat intelligence
- **Krebs on Security**: Cybersecurity news and analysis
- **CERT-In India**: Indian government cybersecurity threats
- **Spamhaus DROP**: Spam and malware IP blocklists

## 🛠️ Installation

### Prerequisites

- Python 3.7+
- MySQL 5.7+ or 8.0+
- Internet connection for data sources

### Setup

1. **Clone or download the project files**

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MySQL database**:
   ```bash
   mysql -u root -p < database_schema.sql
   ```

4. **Configure database connection** (if needed):
   - Edit `app.py` and `cyber_feeds_oop.py`
   - Update host, user, password, and database name

## 🚀 Usage

### Quick Start

Run the startup script:
```bash
python run_app.py
```

This will:
1. Check dependencies and database connection
2. Give you options to process feeds and/or start the web dashboard
3. Launch the web interface at `http://localhost:5000`

### Manual Usage

1. **Process cyber feeds**:
   ```bash
   python cyber_feeds_oop.py
   ```

2. **Start web dashboard**:
   ```bash
   python app.py
   ```

3. **Open your browser** and go to `http://localhost:5000`

## 📱 Dashboard Features

### Main Dashboard
- **Statistics Cards**: Total incidents, critical alerts, active alerts, monitored sources
- **Interactive Charts**: Severity and sector breakdowns
- **Real-time Data**: Auto-refresh capability
- **Incident List**: Detailed view of all incidents with filtering

### Filtering & Search
- Filter by severity (Critical, High, Medium, Low)
- Filter by sector (Financial, Healthcare, Government, etc.)
- Filter by category (Malware, Phishing, Vulnerability, etc.)
- Search incidents by keywords

### Alert Management
- View all generated alerts
- See alert status and recipients
- Track alert history

## 🔧 API Endpoints

- `GET /` - Main dashboard
- `GET /api/incidents` - Get incidents with filtering
- `GET /api/statistics` - Get statistics data
- `POST /api/refresh` - Refresh data from sources
- `GET /api/incident/<id>` - Get specific incident details

## 📊 Database Schema

The system uses three main tables:

- **`raw_feeds`**: Stores original data from sources
- **`incidents`**: Stores processed and analyzed incidents
- **`alert`**: Stores generated alerts

## 🏗️ Architecture

### OOP Classes

- **`CyberFeedManager`**: Main orchestrator
- **`DataSourceManager`**: Manages data sources
- **`IncidentAnalyzer`**: Analyzes and categorizes incidents
- **`SectorCategorizer`**: Categorizes by business sector
- **`AlertGenerator`**: Generates alerts
- **`DatabaseManager`**: Handles database operations

### Data Flow

1. **Data Collection**: Fetch data from multiple sources
2. **Processing**: Analyze and categorize incidents
3. **Storage**: Store in MySQL database
4. **Alerting**: Generate alerts for high-priority incidents
5. **Display**: Show in web dashboard

## 🔍 Incident Categories

- **Malware**: Ransomware, trojans, botnets, viruses
- **Phishing**: Credential theft, spoofing, scams
- **Vulnerability**: CVE reports, security holes, exploits
- **DDoS**: Denial of service attacks
- **Data Breach**: Data leaks, stolen information
- **Spam/Blacklist**: Spam activities, blocklist entries

## 🏢 Sector Classification

- **Financial**: Banks, payment systems, fintech
- **Healthcare**: Hospitals, medical systems, pharma
- **Government**: Public sector, ministries, departments
- **Education**: Schools, universities, academic institutions
- **Technology**: IT companies, software, hardware
- **Energy**: Power, utilities, oil & gas
- **Transportation**: Logistics, shipping, aviation
- **Retail**: E-commerce, stores, marketplaces

## 🚨 Alert System

Alerts are automatically generated for:
- **Critical** incidents: Security team + Management
- **High** incidents: Security team
- **Medium** incidents: Security team

## 🔄 Real-time Updates

The dashboard supports:
- Manual refresh button
- Auto-refresh every 30 seconds
- Real-time statistics updates
- Live incident filtering

## 🛠️ Troubleshooting

### Common Issues

1. **Database Connection Error**:
   - Check MySQL is running
   - Verify credentials in `app.py`
   - Run `database_schema.sql`

2. **Import Errors**:
   - Install missing packages: `pip install -r requirements.txt`

3. **No Data Showing**:
   - Run `python cyber_feeds_oop.py` first
   - Check data sources are accessible

4. **Web App Not Starting**:
   - Check port 5000 is available
   - Try different port in `app.py`

## 📈 Future Enhancements

- [ ] Email/SMS alert delivery
- [ ] More Indian cybersecurity sources
- [ ] User authentication system
- [ ] Advanced analytics and reporting
- [ ] Mobile app interface
- [ ] Machine learning threat detection

## 🤝 Contributing

This is a project for Advanced Programming course. Feel free to suggest improvements or report issues.

## 📄 License

This project is for educational purposes.

---

**Note**: This system is designed for educational and research purposes. For production use, additional security measures and compliance features should be implemented.


