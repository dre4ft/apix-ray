# APIX-Ray Web UI

Modern dashboard for controlling and monitoring the APIX-Ray pentest agent.

## 📁 Files

- **webapp.html** - Main dashboard interface with scan configuration and results
- **style.css** - Modern dark-themed styling with responsive design
- **script.js** - Frontend logic for API integration and real-time updates

## 🚀 Usage

### Start the API Server
```bash
cd web_app
python api.py
```
The API will run on `http://localhost:8080`

### Open the Dashboard
```bash
# In another terminal, serve the static files
cd web_app/static
python -m http.server 8800
```

Then open: `http://localhost:8800/webapp.html`

## 🎨 Features

### Dashboard Tab
- **Real-time Status**: Monitor scan progress
- **Configuration**: Set target URL, LLM type, vulnerabilities to test
- **Metrics**: View endpoint discovery, tests generated, severity breakdown
- **Target Info**: Track current scan target and configuration

### Logs Tab
- **Live Logs**: Real-time scan execution logs with timestamps
- **Log Types**: Info, Success, Warning, Error messages
- **Clear Logs**: Reset log history

### Results Tab
- **Vulnerabilities List**: All found vulnerabilities with severity
- **Details**: Endpoint, payload, response for each vulnerability
- **Export**: Generate JSON report of findings

## ⚙️ API Endpoints

The frontend consumes these API endpoints:

- `GET /health` - Health check
- `GET /llm/models` - Available LLM models
- `POST /start_scan` - Start a new scan
- `GET /scan_status/{scan_id}` - Get scan status and progress
- `GET /scan_logs/{scan_id}` - Get scan logs
- `GET /scan_results/{scan_id}` - Get scan results

## 🌐 CORS Configuration

The API has CORS enabled for all origins (can be restricted in production):
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## 🎯 Quick Start

1. **Ensure the API is running**: `http://localhost:8080`
2. **Open the dashboard**: `http://localhost:8800/webapp.html`
3. **Configure**: Set target URL and select vulnerabilities
4. **Start Scan**: Click "Start Scan" button
5. **Monitor**: Watch logs and results in real-time
6. **Export**: Download report when complete

## 🎨 UI Customization

### Colors
Edit `style.css` root variables:
```css
:root {
    --primary-color: #2563eb;
    --danger-color: #ef4444;
    --success-color: #22c55e;
    /* ... etc */
}
```

### API Base URL
Edit in `script.js`:
```javascript
const API_BASE = 'http://localhost:8080';
```

## 📱 Responsive Design

The dashboard is responsive and works on:
- Desktop (full layout with 3-column grid)
- Tablet (adapted grid)
- Mobile (single column, simplified UI)

## 🔧 Development

To modify the UI:
1. Edit `style.css` for styling
2. Edit `webapp.html` for structure
3. Edit `script.js` for functionality
4. Changes apply immediately on page refresh

## 📝 Notes

- All timestamps are shown in local browser time
- Scan results are stored in memory (lost on page refresh)
- Export feature downloads results as JSON
- Real-time updates poll every 2 seconds during scan
