# Network Intrusion Detection Dashboard

A real-time web application that generates network traffic from the NSL-KDD dataset and provides intrusion detection predictions using machine learning.

## Features

- **Real-time Network Traffic Simulation**: Generates realistic network flows at the network level
- **Machine Learning Predictions**: Uses Random Forest classifier trained on NSL-KDD dataset
- **Beautiful Dashboard**: Modern, responsive web interface with real-time charts
- **Network-level Traffic**: Simulates actual network connections without requiring packet injection
- **Attack Pattern Detection**: Identifies various attack types including port scans, DoS attacks, and brute force attempts

## Architecture

The application consists of several components:

1. **Network Traffic Generator** (`traffic_generator.py`): Simulates realistic network flows with various traffic patterns
2. **ML Model Integration** (`app.py`): Loads the trained Random Forest model and makes predictions
3. **Web Dashboard** (`templates/dashboard.html`): Beautiful real-time dashboard for visualization
4. **Flask Backend**: RESTful API endpoints for real-time data streaming

## Network Traffic Simulation

The traffic generator creates realistic network flows that simulate:

- **Web browsing**: HTTP/HTTPS traffic to various servers
- **Email**: SMTP, POP3, IMAP traffic
- **DNS queries**: Domain name resolution requests
- **SSH connections**: Secure shell access
- **FTP transfers**: File transfer protocol sessions

### Attack Patterns

The system can generate various attack patterns:

- **Port Scans**: Rapid connection attempts across multiple ports
- **DoS Attacks**: High-volume traffic to overwhelm services
- **Brute Force**: Repeated login attempts on SSH/FTP/Telnet

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- Windows (PowerShell support)

### Quick Start

1. **Double-click `start_dashboard.bat`** - This will automatically:
   - Create a virtual environment
   - Install all dependencies
   - Start the Flask application

2. **Open your browser** and navigate to: `http://localhost:5000`

### Manual Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## Usage

1. **Start the Application**: Run `start_dashboard.bat` or use manual setup
2. **Open Dashboard**: Navigate to `http://localhost:5000`
3. **Start Simulation**: Click "Start Simulation" button
4. **Monitor Traffic**: Watch real-time traffic analysis and predictions
5. **Stop Simulation**: Click "Stop Simulation" when done

## Dashboard Features

### Statistics Cards
- **Total Packets**: Overall traffic volume
- **Normal Traffic**: Legitimate network activity
- **Threats Detected**: Number of attacks identified
- **Attack Rate**: Percentage of malicious traffic

### Real-time Charts
- **Traffic Over Time**: Line chart showing normal vs attack traffic trends
- **Attack Types Distribution**: Doughnut chart of attack classification

### Live Traffic Feed
- Real-time stream of network packets
- Color-coded by threat level (green=normal, red=attack)
- Confidence scores for each prediction
- Network connection details (IPs, ports, protocols)

## Technical Details

### Feature Engineering

The application maps network-level traffic to KDD Cup features:

- **Duration**: Connection duration
- **Protocol Type**: TCP, UDP, ICMP
- **Service**: HTTP, SSH, FTP, DNS, etc.
- **Flag**: TCP connection state
- **Src/Dst Bytes**: Traffic volume in both directions
- **Urgent**: TCP urgent pointer flag

### Machine Learning Model

- **Algorithm**: Random Forest Classifier
- **Features**: 7 core network features mapped from KDD Cup dataset
- **Training Data**: NSL-KDD training set
- **Performance**: Real-time prediction with confidence scores

### Network Simulation

- **IP Address Generation**: Realistic internal (RFC 1918) and external networks
- **Traffic Patterns**: Based on real-world network behavior
- **Attack Simulation**: Mimics actual attack patterns and signatures
- **Timing**: Exponential distribution for realistic packet timing

## API Endpoints

- `GET /`: Main dashboard
- `GET /api/start_simulation`: Start traffic generation
- `GET /api/stop_simulation`: Stop traffic generation
- `GET /api/traffic_data`: Get recent traffic packets
- `GET /api/statistics`: Get aggregated statistics
- `GET /api/live_feed`: Get live traffic feed

## File Structure

```
intrusion_detection_webapp/
├── app.py                 # Main Flask application
├── traffic_generator.py   # Network traffic simulation
├── requirements.txt       # Python dependencies
├── start_dashboard.bat    # Windows startup script
├── README.md             # This file
└── templates/
    └── dashboard.html    # Web dashboard template
```

## Dependencies

- Flask 2.3.3 - Web framework
- NumPy 1.24.3 - Numerical computing
- Pandas 2.0.3 - Data manipulation
- Scikit-learn 1.3.0 - Machine learning
- Werkzeug 2.3.7 - WSGI utilities

## Security Notes

This application is designed for educational and demonstration purposes. The traffic simulation:

- Does NOT inject actual packets into the network
- Does NOT require administrative privileges
- Simulates traffic flows without real network impact
- Is safe to run on any network environment

## Troubleshooting

### Common Issues

1. **Python not found**: Install Python 3.8+ and add to PATH
2. **Permission errors**: Run as administrator if needed
3. **Port 5000 in use**: Change port in `app.py` (line with `app.run()`)
4. **Model loading fails**: Ensure data files are in correct location (`../data/`)

### Data File Location

Make sure the NSL-KDD dataset files are located at:
```
../data/KDDTrain+.txt
../data/KDDTest+.txt
```

## Contributing

This project demonstrates network intrusion detection concepts. Contributions are welcome for:

- Additional attack pattern simulation
- Enhanced visualization features
- Performance optimizations
- Additional ML models

## License

Educational use - Based on NSL-KDD dataset research.
