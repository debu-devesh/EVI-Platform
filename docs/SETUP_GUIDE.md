# 🚀 Complete Setup Guide - EVI Repository

This guide ensures that anyone who clones the repository can get **full functionality** working.

---

## ✅ What's Included in the Repository

### ✅ **Available (Full Functionality)**
- ✅ All source code
- ✅ All Python dependencies (`requirements.txt`)
- ✅ Database setup scripts (auto-create databases on first run)
- ✅ Configuration templates
- ✅ Documentation and installation guides
- ✅ Quick start scripts

### ⚠️ **What You Need to Set Up**

1. **Python Environment** - Install Python 3.7+
2. **Dependencies** - Install from `requirements.txt`
3. **LM Studio** - For AI Chat Assistant (optional but recommended)
4. **Environment Variables** - Create `.env` file (optional, has defaults)

---

## 📋 Step-by-Step Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/debu-devesh/EVI-SCAN.git
cd EVI-SCAN
```

### Step 2: Install Python Dependencies

**Windows:**
```bash
cd FORENSIC
python scripts/setup_with_lm_studio.py
```

**Mac/Linux:**
```bash
cd FORENSIC
python3 scripts/setup_with_lm_studio.py
```

This installs:
- Flask (web framework)
- pandas (data processing)
- rapidfuzz (fuzzy matching)
- orjson (fast JSON)
- requests (API calls)
- bcrypt (password hashing)
- cryptography (encryption)
- reportlab (PDF generation)

### Step 3: Set Up Environment Variables (Optional)

Create a `.env` file in the `FORENSIC` directory:

```bash
# Copy the example (if it exists)
cp .env.example .env

# Or create manually
```

**Default values work for development:**
- `SECRET_KEY` - Auto-generated if not set
- `DEV_MODE` - Set to `True` for development (bypasses auth)
- `LM_STUDIO_URL` - Defaults to `http://localhost:1234`

**For Production:**
```env
SECRET_KEY=your-secret-key-here-change-in-production
DEV_MODE=False
LM_STUDIO_URL=http://localhost:1234
```

### Step 4: Database Setup (Automatic)

**Databases are auto-created on first run!**

The application automatically creates:
1. **Session Database** (`database/data/sessions.db`) - Created by `init_session_db()`
2. **Authentication Database** (`Authentication/evi_scan.db`) - Created by `init_db()` in `Authentication/app.py`
3. **Forensic Data Databases** - Created per UFDR file when you upload

**No manual database setup required!** Just run the application.

### Step 5: Install LM Studio (For AI Chat)

1. Download from: https://lmstudio.ai/
2. Install and launch LM Studio
3. Download model: `Qwen/Qwen2.5-7B-Instruct`
4. Start LM Studio server (Local Server tab)
5. Keep it running while using EVI

**Note:** AI Chat works without LM Studio, but responses will be limited.

### Step 6: Start the Application

**Option A: Quick Start (Recommended)**
```bash
# Windows
cd FORENSIC
scripts\QUICK_START.bat

# Mac/Linux
cd FORENSIC
chmod +x scripts/QUICK_START.sh
./scripts/QUICK_START.sh
```

**Option B: Manual Start**
```bash
cd FORENSIC
python scripts/start_enhanced_web_interface.py
```

### Step 7: Access the Web Interface

1. Open browser: `http://localhost:5000`
2. **Development Mode** (`DEV_MODE=True`): Direct access to Case Manager
3. **Production Mode** (`DEV_MODE=False`): Login page → Create account → Access Case Manager

---

## 🔍 Verification Checklist

After setup, verify everything works:

### ✅ Basic Functionality
- [ ] Web interface loads at `http://localhost:5000`
- [ ] Can create a new case
- [ ] Can upload a UFDR file (ZIP, JSON, or XML)
- [ ] Can view uploaded files

### ✅ Database Functionality
- [ ] Session database created (`database/data/sessions.db`)
- [ ] Authentication database created (`Authentication/evi_scan.db`)
- [ ] Can create user account (if `DEV_MODE=False`)
- [ ] Can login (if `DEV_MODE=False`)

### ✅ AI Chat (Requires LM Studio)
- [ ] LM Studio server running on `http://localhost:1234`
- [ ] Can ask questions in AI Chat tab
- [ ] Receives AI responses

### ✅ Forensic Analysis
- [ ] Can query uploaded data
- [ ] Can view contacts, messages, calls
- [ ] Can export PDF reports
- [ ] Pattern detection works

---

## 🛠️ Troubleshooting

### Issue: "Module not found"

**Solution:**
```bash
cd FORENSIC
python scripts/setup_with_lm_studio.py
```

### Issue: "Database not found"

**Solution:**
- Databases are auto-created on first run
- Check file permissions in `database/data/` and `Authentication/`
- Ensure write permissions exist

### Issue: "Port 5000 already in use"

**Solution:**
- Close other applications using port 5000
- Or change port in `web_interface.py`:
  ```python
  app.run(host='0.0.0.0', port=5001)  # Change 5000 to 5001
  ```

### Issue: "AI Chat not working"

**Solution:**
1. Ensure LM Studio is installed and running
2. Verify server is running: `http://localhost:1234`
3. Check model is loaded in LM Studio
4. AI Chat will work without LM Studio but with limited functionality

### Issue: "Authentication required"

**Solution:**
- **Development:** Set `DEV_MODE=True` in `web_interface.py` or `.env`
- **Production:** Create account via signup page

---

## 📦 What Gets Created Automatically

When you first run the application:

1. **`database/data/sessions.db`** - Session and case management
2. **`Authentication/evi_scan.db`** - User authentication
3. **`FORENSIC/data/uploads/`** - Uploaded UFDR files
4. **`FORENSIC/data/extracted_ufdrs/`** - Extracted UFDR data
5. **`audit.log`** - Audit trail (if security enabled)

**All of these are created automatically - no manual setup needed!**

---

## 🎯 Full Functionality Checklist

After following this guide, you should have:

✅ **Core Features:**
- Web interface running
- Case management
- File upload and parsing
- Data extraction and querying
- Pattern detection
- PDF report generation

✅ **Security Features:**
- User authentication (if `DEV_MODE=False`)
- Role-based access control
- Audit logging
- Data encryption

✅ **AI Features:**
- Natural language queries
- AI chat assistant (with LM Studio)
- Pattern analysis
- Streaming responses

✅ **Database Features:**
- Session persistence
- Chat history
- Case management
- User management

---

## 📚 Additional Resources

- [README.md](README.md) - Feature overview
- [INSTALLATION.md](INSTALLATION.md) - Detailed installation guide
- [FOLDER_STRUCTURE.md](FOLDER_STRUCTURE.md) - Project structure
- [docs/DOCUMENTATION_INDEX.md](docs/DOCUMENTATION_INDEX.md) - Documentation map
- [docs/GITHUB_RELEASE_CHECKLIST.md](docs/GITHUB_RELEASE_CHECKLIST.md) - Publish checklist

---

## ✅ Summary

**Yes, full functionality is available after cloning!**

Everything needed is in the repository:
- ✅ Source code
- ✅ Dependencies list
- ✅ Setup scripts
- ✅ Auto-created databases
- ✅ Default configurations

**You just need to:**
1. Install Python 3.7+
2. Run `setup_with_lm_studio.py`
3. (Optional) Install LM Studio for AI Chat
4. Start the application

**That's it!** 🎉











