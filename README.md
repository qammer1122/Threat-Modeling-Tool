# 🔐 Threat Modeling Tool
## STRIDE Methodology with DREAD Risk Scoring

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3.3-000000?style=flat-square&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)
![STRIDE](https://img.shields.io/badge/Methodology-STRIDE-red?style=flat-square)
![DREAD](https://img.shields.io/badge/Scoring-DREAD-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat-square)

> A Python-based web application for automated threat modeling using
> the STRIDE methodology and DREAD risk scoring framework.
> Identifies security threats across DFD components, calculates
> risk scores, fetches live CVE data, and generates mitigation reports.

---

## 📋 Project Overview

| Detail | Info |
|---|---|
| **Duration** | October 15 – November 15, 2024 |
| **Language** | Python 3.8+ |
| **Framework** | Flask + Flask-SocketIO |
| **Database** | SQLite |
| **Methodology** | STRIDE + DREAD |
| **CVE Integration** | CIRCL CVE API |

---

## ✨ Features

- ✅ **STRIDE Threat Analysis** — Identifies threats across all 6 STRIDE categories
- ✅ **DREAD Risk Scoring** — Quantifies risk with 5-dimension scoring (1–10 scale)
- ✅ **DFD Builder** — Create Data Flow Diagrams with processes, data stores, external entities
- ✅ **Live CVE Integration** — Fetches real CVE data from CIRCL API for identified threats
- ✅ **SQLite Database** — Stores threats, components, and reports persistently
- ✅ **Mitigation Reports** — Generates structured remediation recommendations
- ✅ **REST API** — Full API for DFD creation, threat analysis, and report management
- ✅ **Dark Theme UI** — Professional cybersecurity-themed web interface

---

## 🏗️ Project Structure

```
Threat-Modeling-Tool/
├── app.py                      ← Flask application entry point
├── requirements.txt            ← Python dependencies
│
├── backend/
│   ├── stride.py               ← STRIDE threat analysis engine
│   ├── dread.py                ← DREAD risk scoring engine
│   ├── dfd.py                  ← DFD graph creation (NetworkX)
│   ├── database.py             ← SQLite database operations
│   └── cve.py                  ← CVE data fetching (CIRCL API)
│
├── frontend/
│   ├── routes.py               ← Flask API routes & blueprints
│   ├── templates/
│   │   └── index.html          ← Main web interface
│   └── static/
│       ├── styles.css          ← Dark cybersecurity theme
│       └── script.js           ← Frontend logic & API calls
│
├── utils/
│   ├── threat_utils.py         ← Threat identification & prioritization
│   └── graph_utils.py          ← Graph analysis utilities
│
└── database/
    └── threat_model.db         ← SQLite database (auto-created)
```

---

## 🎯 STRIDE Methodology

The tool analyzes threats across all 6 STRIDE categories:

| Category | Description | Applicable To |
|---|---|---|
| **S**poofing | Impersonating users or components | Processes, External Entities |
| **T**ampering | Unauthorized data modification | All Components |
| **R**epudiation | Denying performed actions | Processes, External Entities |
| **I**nformation Disclosure | Exposing sensitive data | All Components |
| **D**enial of Service | Disrupting service availability | All Components |
| **E**levation of Privilege | Gaining unauthorized permissions | Processes |

---

## 📊 DREAD Risk Scoring

Each threat is scored across 5 dimensions on a 1–10 scale:

| Dimension | Question |
|---|---|
| **D**amage | How bad would an attack be? |
| **R**eproducibility | How easy is it to reproduce? |
| **E**xploitability | How much effort to launch the attack? |
| **A**ffected Users | How many people will be impacted? |
| **D**iscoverability | How easy is the threat to discover? |

**Total Score** = Average of all 5 dimensions

| Score Range | Severity |
|---|---|
| 8.0 – 10.0 | 🔴 Critical |
| 6.0 – 7.9 | 🟠 High |
| 4.0 – 5.9 | 🟡 Medium |
| 0.0 – 3.9 | 🟢 Low |

---

## 🗄️ Database Schema

```sql
-- DFD Components
dfd_components (id, name, component_type, description, created_at)

-- Identified Threats
threats (id, component_id, category, name, description,
         severity, dread_score, mitigation, status, created_at)

-- Reports
reports (id, title, summary, threats_json, created_at)
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/qammer1122/Threat-Modeling-Tool.git
cd Threat-Modeling-Tool

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python app.py

# 4. Open in browser
# http://localhost:5000
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Main web interface |
| `GET` | `/api/dfd/default` | Get sample DFD |
| `POST` | `/api/dfd/create` | Create custom DFD |
| `POST` | `/api/analyze` | Run STRIDE analysis |
| `GET` | `/api/threats` | Get all saved threats |
| `GET` | `/api/reports` | Get all reports |
| `POST` | `/api/reports/save` | Save a report |

### Example API Usage

```python
import requests

# Run STRIDE analysis
response = requests.post('http://localhost:5000/api/analyze',
    json={
        'components': [
            {'name': 'Web Server', 'type': 'process',
             'sensitivity': 'high'},
            {'name': 'Database', 'type': 'data_store',
             'sensitivity': 'critical'},
            {'name': 'User', 'type': 'external_entity',
             'sensitivity': 'low'}
        ]
    }
)

data = response.json()
print(f"Threats found: {data['total_threats']}")
print(f"Critical: {data['summary']['by_severity']['Critical']}")
```

### Example Response

```json
{
  "status": "success",
  "total_threats": 14,
  "summary": {
    "total": 14,
    "by_severity": {
      "Critical": 8,
      "High": 4,
      "Medium": 2,
      "Low": 0
    }
  },
  "threats": [
    {
      "component": "Database",
      "category": "Elevation of Privilege",
      "severity": "Critical",
      "dread_score": 10.0,
      "dread_breakdown": {
        "damage": 10.0,
        "reproducibility": 7.5,
        "exploitability": 9.0,
        "affected_users": 10.0,
        "discoverability": 6.0
      },
      "mitigations": [
        "Apply principle of least privilege",
        "Regularly patch and update systems",
        "Implement proper authorization checks",
        "Use role-based access control (RBAC)"
      ]
    }
  ]
}
```

---

## 🧪 Test Results

```
✅ All imports successful
✅ Database initialized (SQLite)
✅ DFD created: 6 components, 6 flows
✅ DREAD scoring working (score: 8.76 for Web Server)
✅ STRIDE analysis: 27 threats identified
   Critical: 17 | High: 7 | Medium: 3 | Low: 0
✅ Mitigation report: all 6 categories covered
✅ Database save/retrieve working
✅ Flask app starts successfully
✅ All API endpoints responding correctly
```

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| **Python** | Core application language |
| **Flask** | Web framework |
| **Flask-SocketIO** | Real-time communication |
| **NetworkX** | DFD graph modeling |
| **SQLite** | Persistent data storage |
| **CIRCL CVE API** | Live CVE threat intelligence |
| **HTML/CSS/JS** | Frontend web interface |

---

## 📚 Key Skills Demonstrated

- ✅ Python OOP and modular application design
- ✅ Flask REST API development
- ✅ STRIDE threat modeling methodology
- ✅ DREAD quantitative risk scoring
- ✅ SQLite database design and management
- ✅ Graph-based DFD modeling with NetworkX
- ✅ External API integration (CVE database)
- ✅ Cybersecurity framework implementation

---

## 🎓 Learning Outcomes

Through this project I gained:

- Deep understanding of STRIDE threat modeling framework
- Ability to quantify security risks using DREAD scoring
- Experience building security analysis tools in Python
- Knowledge of CVE databases and threat intelligence APIs
- Skills in designing RESTful security APIs
- Understanding of Data Flow Diagram analysis

---

## 📞 Contact

**Qammer Abbas**
📧 [qammer1122@gmail.com](https://mail.google.com/mail/?view=cm&fs=1&to=qammer1122@gmail.com)
🔗 [LinkedIn](https://linkedin.com/in/qammer1122)
🐙 [GitHub](https://github.com/qammer1122)
🛡️ [TryHackMe](https://tryhackme.com/p/qammer1122)
