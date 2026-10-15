# 📦 Complete Installation Guide - EVI

This guide will walk you through installing EVI from scratch, from cloning the repository to running the application.

---

## 📋 Prerequisites

Before you begin, make sure you have:

1. **Python 3.7 or higher**
   - Download from: https://www.python.org/downloads/
   - ⚠️ **IMPORTANT**: During installation, check "Add Python to PATH"
   - Verify installation: Open terminal/command prompt and run `python --version`

2. **Git** (for cloning the repository)
   - Download from: https://git-scm.com/downloads
   - Verify installation: Run `git --version`

3. **LM Studio** (Required for AI Chat Assistant feature)
   - Download from: https://lmstudio.ai/
   - Free and open-source
   - We'll install this in Step 3

---

## 🚀 Step-by-Step Installation

### Step 1: Clone the Repository

Open your terminal/command prompt and run:

```bash
# Clone the repository
git clone https://github.com/debu-devesh/EVI.git

# Navigate to the project directory
cd EVI/FORENSIC
```

**Expected Output:**
```
Cloning into 'EVI'...
remote: Enumerating objects: ...
remote: Counting objects: ...
...
```

---

### Step 2: Install Python Dependencies

Run the setup script to install all required Python packages:

**Windows:**
```bash
python scripts/setup_with_lm_studio.py
```

**Mac/Linux:**
```bash
python3 scripts/setup_with_lm_studio.py
```

**What this installs:**
- Flask (web framework)
- pandas (data processing)
- rapidfuzz (fuzzy string matching)
- orjson (fast JSON processing)
- requests (for LM Studio API)

**Expected Output:**
```
🔧 EVI - Complete Setup (Including AI Chat)
======================================================================
Step 1: Checking Python packages...
----------------------------------------------------------------------
✅ flask is already installed
✅ pandas is already installed
...
✅ All Python packages are installed!
```

---

### Step 3: Install LM Studio (For AI Chat Assistant)

#### 3.1 Download and Install LM Studio

1. Visit: https://lmstudio.ai/
2. Click "Download" for your operating system (Windows/Mac/Linux)
3. Run the installer and follow the installation wizard
4. Launch LM Studio

#### 3.2 Download the AI Model

1. In LM Studio, click on the **"Search"** tab (left sidebar)
2. In the search box, type: `Qwen/Qwen2.5-7B-Instruct`
3. Find the model in the results (usually from "Qwen" or "QwenLM")
4. Click the **"Download"** button
5. Wait for the download to complete (~4-5GB, one-time download)

**Note:** The model name is `Qwen/Qwen2.5-7B-Instruct` (7B parameters, optimized for better performance with 4GB+ VRAM). Qwen 2.5 7B Instruct provides excellent performance for forensic analysis tasks with improved reasoning capabilities.

#### 3.3 Start LM Studio Server

1. In LM Studio, click on the **"Local Server"** tab (left sidebar)
2. Make sure the model `Qwen/Qwen2.5-7B-Instruct` is selected in the dropdown
3. Click the **"Start Server"** button
4. You should see: "Server running at http://localhost:1234"
5. **Keep LM Studio running** while using EVI

**Important:** The LM Studio server must be running for the AI Chat Assistant to work.

---

### Step 4: Verify Setup

Run the setup script again to verify everything is configured correctly:

```bash
# Windows
python scripts/setup_with_lm_studio.py

# Mac/Linux
python3 scripts/setup_with_lm_studio.py
```

**Expected Output:**
```
✅ All Python packages are installed!
======================================================================
Step 2: Checking LM Studio (Required for AI Chat Assistant)...
----------------------------------------------------------------------
   ✅ LM Studio server is running with 1 model(s) loaded
   Loaded models:
   - Qwen/Qwen2.5-7B-Instruct

======================================================================
🎉 Setup Complete! Everything is ready!
======================================================================
```

---

### Step 5: Start the Application

You have two options to start the application:

#### Option A: Quick Start Script (Recommended)

**Windows:**
```bash
scripts\QUICK_START.bat
```

**Mac/Linux:**
```bash
chmod +x scripts/QUICK_START.sh
./scripts/QUICK_START.sh
```

#### Option B: Manual Start

**Windows:**
```bash
python scripts/start_enhanced_web_interface.py
```

**Mac/Linux:**
```bash
python3 scripts/start_enhanced_web_interface.py
```

**Expected Output:**
```
 * Serving Flask app 'web_interface'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

---

### Step 6: Access the Web Interface

1. Open your web browser (Chrome, Firefox, Edge, Safari, etc.)
2. Navigate to: `http://localhost:5000`
3. **Development Mode**: If `DEV_MODE=True` is set, you'll go directly to the Case Manager
4. **Production Mode**: You'll see the login page - create an account or login
5. After login, you'll see the Case Manager interface where you can create cases and upload UFDR files!

---

### Step 7: Test the Application

1. **Create a Case (if in Production Mode):**
   - From the Case Manager, click "Create New Case"
   - Enter case details (name, description, etc.)
   - Save the case

2. **Upload a Test File:**
   - Click "Upload UFDR File" button
   - Select a ZIP file from `FORENSIC/data/UFDR's(new)/` (if available)
   - Or use your own UFDR JSON or ZIP file
   - The file will be associated with your current case

3. **Try a Query:**
   - Type: `"show messages with external partners"`
   - Click "Analyze" or press Enter
   - You should see results!

4. **Test AI Chat (if LM Studio is running):**
   - Click on the "AI Chat" tab
   - Type a question about your uploaded data
   - The AI should respond with forensic analysis

5. **Export PDF Report:**
   - Click "Export PDF" to generate a comprehensive report
   - The report includes all analysis results and findings

---

## ✅ Installation Complete!

You're all set! The application is now running and ready to use.

---

## 🔧 Troubleshooting

### Issue: "Python is not recognized"

**Solution:**
1. Reinstall Python from https://www.python.org/downloads/
2. Make sure to check "Add Python to PATH" during installation
3. Restart your terminal/command prompt

### Issue: "Module not found" or "No module named 'flask'"

**Solution:**
```bash
cd FORENSIC
python scripts/setup_with_lm_studio.py
```

### Issue: "Port 5000 already in use"

**Solution:**
1. Close other applications using port 5000
2. Or wait a few minutes for the port to be released
3. You can also change the port in `web_interface.py` if needed

### Issue: "LM Studio connection failed" or "AI Chat not working"

**Solution:**
1. Make sure LM Studio is installed and running
2. Verify the model `Qwen/Qwen2.5-7B-Instruct` is downloaded
3. Start the LM Studio server from the "Local Server" tab
4. Check that the server is running on `http://localhost:1234`
5. Try restarting both LM Studio and the application

### Issue: "Permission denied" (Mac/Linux)

**Solution:**
- Use `python3` instead of `python`
- Or run with appropriate permissions: `sudo python3 ...`

### Issue: "Git is not recognized"

**Solution:**
1. Install Git from https://git-scm.com/downloads
2. Restart your terminal/command prompt

### Issue: Slow AI responses

**Solution:**
- Ensure you're using `Qwen/Qwen2.5-7B-Instruct`
- Check that your GPU is being utilized in LM Studio
- Close other resource-intensive applications
- For systems with limited VRAM (4GB), consider using quantization in LM Studio

### Issue: "Authentication required" or login issues

**Solution:**
1. **For Development/Testing:**
   - Set environment variable: `export DEV_MODE=True` (Linux/Mac) or `set DEV_MODE=True` (Windows)
   - Or edit `web_interface.py` and set `DEV_MODE = True`
   - This bypasses authentication for easier testing

2. **For Production:**
   - Use the signup page to create an account
   - Login with your credentials
   - If database is missing, run: `python Authentication/setup_database.py`

3. **Database Issues:**
   - Check that `Authentication/evi_scan.db` exists
   - If missing, run the setup script: `python Authentication/setup_database.py`
   - Check file permissions on the database file

---

## 📚 Next Steps

- Read the [README.md](README.md) for feature overview
- Check [FOLDER_STRUCTURE.md](FOLDER_STRUCTURE.md) to understand the project layout
- Review [docs/setup/SETUP_SUMMARY.md](docs/setup/SETUP_SUMMARY.md) for quick reference
- Explore the [Documentation](docs/) folder for detailed guides

---

## 🆘 Need Help?

- Check the [Troubleshooting](#-troubleshooting) section above
- Review the [README.md](README.md) documentation
- Open an issue on [GitHub](https://github.com/debu-devesh/EVI/issues)

---

**Happy Forensics! 🔍**

