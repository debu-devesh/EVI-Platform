# 📁 EVI - Folder Structure Guide

This document provides a clear overview of the project's folder structure and what each folder/file does.

## 🗂️ Complete Folder Structure

```
EVI/
│
├── 📄 README.md                    # Main project documentation
├── 📄 CHANGELOG.md                 # Version history and changes
├── 📄 CONTRIBUTING.md              # How to contribute to the project
├── 📄 LICENSE                      # Apache License 2.0
├── 📄 NOTICE                       # Copyright, attribution, forensic use disclaimer
├── 📄 .gitignore                   # Files to ignore in Git
│
├── 📁 EBI-scan/                    # FastAPI + Vite: image search, faces, object detection
│
├── 📁 FORENSIC/                    # Main application folder
│   ├── 📄 web_interface.py         # Main Flask web application (START HERE!)
│   ├── 📄 session_db.py           # Session and case management database
│   ├── 📄 security_enhancements.py # Security features
│   ├── 📄 sessions.db              # SQLite database for sessions/cases
│   ├── 📄 README.md                # Module-specific documentation
│   ├── 📄 PROJECT_STRUCTURE.md     # Detailed structure guide
│   ├── 📄 requirements.txt         # All Python dependencies
│   ├── 📄 requirements_minimal.txt # Minimal dependencies (core features only)
│   │
│   ├── 📁 core/                    # Core forensic engine
│   │   ├── __init__.py
│   │   ├── ufdr_processor.py            # Data processor
│   │   ├── ufdr_file_handler.py         # File handling
│   │   ├── ufdr_forensic_command_engine.py  # Command processing
│   │   └── enhanced_data_extractor.py   # Data extraction
│   │
│   ├── 📁 engines/                 # Query and analysis engines
│   │   ├── __init__.py
│   │   ├── nl_query_engine.py           # Natural language queries
│   │   ├── enhanced_nl_query_engine.py  # Enhanced NL queries
│   │   ├── simplified_nl_query_engine.py # Simplified queries
│   │   ├── ai_ufdr_retrieval_engine.py  # AI-powered retrieval
│   │   ├── rag_engine.py                # RAG (Retrieval-Augmented Generation)
│   │   └── smart_analyzer.py            # Smart analysis
│   │
│   ├── 📁 utils/                   # Utility modules
│   │   ├── confidence.py           # Confidence scoring
│   │   ├── ufdr_parser.py          # UFDR file parser
│   │   └── image_citation.py       # Image citation extraction
│   │
│   ├── 📁 templates/               # HTML templates (web UI)
│   │   ├── index.html              # Main page
│   │   ├── enhanced_index.html     # Enhanced UI
│   │   ├── ai_index.html           # AI dashboard
│   │   └── case_manager/           # Case management UI
│   │       ├── case_manager.html   # Main case manager page
│   │       └── *.md                # Case manager documentation
│   │
│   ├── 📁 static/                  # Static web assets
│   │   └── chimes/                 # Audio files (notifications)
│   │       ├── mixkit-alert-quick-chime-766.wav
│   │       ├── mixkit-doorbell-tone-2864.wav
│   │       └── mixkit-relaxing-bell-chime-3109.wav
│   │
│   ├── 📁 data/                    # Data storage
│   │   ├── UFDR's(new)/            # Test/sample ZIP UFDR files
│   │   │   ├── case 1 Kidnapping Conspiracy.zip
│   │   │   ├── case 2 Human Trafficking.zip
│   │   │   ├── case 3 Cyber Fraud  Phishing.zip
│   │   │   ├── case 4 Illegal Surveillance.zip
│   │   │   ├── case 5 Domestic Violence Evidence.zip
│   │   │   ├── case 6 Smuggling Operations.zip
│   │   │   ├── HOMICIDE_UFDR.zip
│   │   │   └── UFDR_FILE.format.zip
│   │   ├── uploads/                # Temporary uploads (auto-cleaned)
│   │   └── uploaded_ufdrs/         # Processed user uploads
│   │
│   ├── 📁 scripts/                 # Setup and utility scripts
│   │   ├── QUICK_START.bat         # Quick start (Windows)
│   │   ├── QUICK_START.sh          # Quick start (Mac/Linux)
│   │   ├── setup_minimal.py        # Minimal setup script
│   │   ├── setup_with_lm_studio.py # Full setup with LM Studio
│   │   ├── start_enhanced_web_interface.py  # Start script
│   │   ├── start_lm_studio_server.py        # LM Studio server starter
│   │   ├── start_lm_studio_server.bat       # LM Studio starter (Windows)
│   │   ├── start_web.bat           # Simple start (Windows)
│   │   └── test_comprehensive_web.bat  # Test script
│   │
│   └── 📁 tests/                   # Test files
│       ├── test_keyword_recognition.py
│       └── simple_example_queries.py
│
├── 📁 docs/                        # Documentation
│   ├── 📁 setup/                   # Setup guides
│   │   ├── START_HERE.txt          # Quick start instructions
│   │   ├── SETUP_SUMMARY.md        # Quick setup reference
│   │   └── START_HERE.txt          # Quick start guide
│   │
│   ├── 📁 guides/                  # Feature guides
│   │   ├── FULL_FUNCTIONALITY_GUIDE.md  # Complete feature guide
│   │
└── 📁 Authentication/              # Authentication system
    ├── 📄 app.py                   # Authentication server
    ├── 📄 evi_scan.db             # Authentication database
    ├── 📄 setup_database.py        # Database setup script
    ├── 📄 requirements.txt        # Auth dependencies
    ├── 📁 templates/               # Authentication templates
    │   ├── forensic_auth.html
    │   ├── privacy.html
    │   ├── signup.html
    │   └── terms.html
    └── 📁 assets/
        ├── 1.jpg
        ├── background.jpg
        └── unnamed.jpg
```

---

## 📖 What Each Folder Does

### 🎯 **FORENSIC/** - Main Application
This is where all the main code lives. **Start here!**

- **`web_interface.py`** - The main file that runs the web application
- **`core/`** - Core forensic analysis engine
- **`engines/`** - Different query engines for analyzing data
- **`utils/`** - Helper functions and utilities
- **`templates/`** - HTML files for the web interface
- **`static/`** - CSS, JavaScript, images, sounds
- **`data/`** - Where your data files go
- **`scripts/`** - Helper scripts for setup and running
- **`tests/`** - Test files to verify everything works

### 📚 **docs/** - Documentation
All the guides and documentation.

- **`setup/`** - How to install and set up
- **`guides/`** - How to use features
- **`archive/`** - Old documentation (for reference)

### 🔐 **Authentication/** - Login System
Optional authentication UI (not required for basic use)

---

## 🚀 Key Files to Know

### For Beginners:
1. **`docs/setup/START_HERE.txt`** - Quick start guide
2. **`FORENSIC/scripts/QUICK_START.bat`** (Windows) or **`QUICK_START.sh`** (Mac/Linux) - Run this to start
3. **`FORENSIC/web_interface.py`** - Main application file

### For Setup:
1. **`FORENSIC/scripts/setup_minimal.py`** - Install dependencies
2. **`FORENSIC/requirements.txt`** - List of all dependencies

### For Testing:
1. **`FORENSIC/data/UFDR's(new)/`** - Test ZIP UFDR files
2. **`FORENSIC/tests/`** - Test scripts

---

## 📂 Data Flow

```
User uploads file
    ↓
FORENSIC/data/uploads/ (temporary)
    ↓
Processed by web_interface.py
    ↓
FORENSIC/data/uploaded_ufdrs/ (stored)
    ↓
Analyzed by core/ and engines/
    ↓
Results shown in templates/
```

---

## 🔍 Finding Things

### "Where do I upload my files?"
→ `FORENSIC/data/uploaded_ufdrs/` (or use the web interface)

### "Where are the test files?"
→ `FORENSIC/data/UFDR's(new)/`

### "How do I start the application?"
→ Run `FORENSIC/scripts/QUICK_START.bat` (Windows) or `QUICK_START.sh` (Mac/Linux)

### "Where is the main code?"
→ `FORENSIC/web_interface.py`

### "Where are the HTML templates?"
→ `FORENSIC/templates/`

### "Where do I add new features?"
→ `FORENSIC/engines/` for query engines, `FORENSIC/core/` for core features

---

## 💡 Tips

1. **Don't modify files in `__pycache__/`** - These are auto-generated
2. **Keep test data in `data/UFDR's(new)/`** - ZIP UFDR test files
3. **User uploads go to `data/uploaded_ufdrs/`** - These are your files
4. **Scripts in `scripts/`** - Use these to start the app
5. **Documentation in `docs/`** - Read these for help

---

## 🎓 For Developers

### Adding a New Feature:
1. **New query engine?** → Add to `FORENSIC/engines/`
2. **New core feature?** → Add to `FORENSIC/core/`
3. **New utility?** → Add to `FORENSIC/utils/`
4. **New UI page?** → Add to `FORENSIC/templates/`

### Testing:
1. Use ZIP files in `FORENSIC/data/UFDR's(new)/`
2. Run tests in `FORENSIC/tests/`
3. Check logs in console output

---

## 📝 Notes

- **`__pycache__/`** folders are auto-generated - ignore them
- **`.gitignore`** tells Git which files to ignore
- **`requirements.txt`** lists all Python packages needed
- All paths are relative to the `FORENSIC/` folder when running scripts

---

<div align="center">

**Need help? Check [README.md](README.md) or [docs/setup/START_HERE.txt](docs/setup/START_HERE.txt)**

</div>

