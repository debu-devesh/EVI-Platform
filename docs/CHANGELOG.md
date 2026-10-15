# Changelog

All notable changes to EVI will be documented in this file.

## [3.2.0] - 2024-12-06

### Changed
- **Model Upgrade**: Switched from Qwen 2.5 3B Instruct to Qwen 2.5 7B Instruct
  - Better reasoning capabilities for forensic analysis
  - Requires 4GB+ VRAM for optimal performance
  - Improved response quality and accuracy
- **RAG Engine**: Disabled by default, using keyword-based extraction instead
  - Reduces dependency requirements
  - Provides similar functionality without sentence-transformers/faiss
  - Can be re-enabled if needed
- **Context Management**: Added smart context truncation
  - Prevents token overflow errors (4096 token limit)
  - Intelligent truncation at sentence/line boundaries
  - Query-aware data prioritization
  - Reserved tokens for system message and response

### Added
- **Context Truncation Function**: `truncate_for_context()` helper
  - Estimates tokens (1 token ≈ 2 characters)
  - Truncates at reasonable boundaries
  - Adds truncation indicators
- **Smart Data Limiting**: Query-intent based data limits
  - Contacts: max 100 items (20 if not contact query)
  - Messages: max 100 items (50 if not message query)
  - Call logs: max 100 items (30 if not call query)
- **Updated Dependencies**:
  - transformers: 4.35.2 (compatible with PyTorch 2.1+)
  - PyTorch: >=2.1.0
  - ReportLab: >=4.0.7

### Fixed
- Fixed context overflow errors when sending large data contexts to LLM
- Fixed PyTorch/transformers version compatibility issues
- Fixed ReportLab missing dependency warning
- Improved error handling for context truncation

### Technical Details
- Updated `prepare_json_for_llm()` to limit data size (8000 chars default)
- Added truncation to all data context points before LLM submission
- Updated semantic extractor calls to truncate output
- Modified both streaming and non-streaming chat endpoints

## [3.0.0] - 2024-12-XX

### Added
- **Adaptive Response System**: Smart query handling that adjusts response style based on query complexity
  - Direct responses for simple queries (counts, lists)
  - Summary with evidence for medium queries
  - Full analysis for complex queries
  - Query complexity detection and intent analysis
- **Enhanced Documentation**: Comprehensive beginner-friendly installation guide
  - Step-by-step instructions for absolute beginners
  - Platform-specific guidance (Windows/Mac/Linux)
  - Detailed troubleshooting section
  - Verification steps for each installation
- **GitHub Preparation**: Complete project setup for GitHub
  - `.env.example` template for environment variables
  - GitHub issue templates (bug reports, feature requests)
  - Pull request template
  - Comprehensive setup guides
- **Code Cleanup**: Removed unnecessary temporary documentation files
  - Cleaned up fix documentation files
  - Removed deprecated approach documentation
  - Updated `.gitignore` to prevent future temporary docs

### Changed
- **Version Bump**: Updated project version to v3.0.0
- **README Enhancement**: Complete rewrite of installation section for beginners
- **Documentation Structure**: Improved organization and clarity
- **Project Organization**: Better file structure and documentation

### Technical Details
- Added `utils/query_analyzer.py` for query complexity detection
- Added `utils/adaptive_prompts.py` for adaptive prompt generation
- Enhanced `.gitignore` with better patterns
- Created GitHub templates and guides

## [2.0.5] - 2024-12-XX

### Added
- **Case Management System**: Comprehensive case organization and tracking
  - Create, update, and manage multiple forensic cases
  - Case metadata (name, description, status, device info)
  - Case-based file organization
  - Case status tracking (Active, Closed, Archived)
- **Session Persistence**: Save and restore analysis sessions
  - SQLite database for session storage (`sessions.db`)
  - Chat history persistence across sessions
  - Session restoration from case ID
  - Query history tracking
  - User preferences storage
- **Authentication System**: Secure user authentication
  - Login/signup functionality with bcrypt password hashing
  - Development mode (`DEV_MODE`) for bypassing authentication during testing
  - Session-based authentication
  - User account management
  - Authentication database (`Authentication/evi_scan.db`)
- **PDF Export**: Comprehensive report generation
  - Export analysis results to PDF format
  - Includes all findings, statistics, and evidence
  - Professional report formatting with ReportLab
  - Downloadable PDF reports
- **Case Manager UI**: Dedicated interface for case management
  - Case creation and editing interface
  - Case list view with status indicators
  - Quick access to case analysis
  - File association with cases
- **Security Enhancements**: Additional security features
  - Password hashing with bcrypt
  - Session management
  - Secure file handling
  - Input validation

### Changed
- **Database Architecture**: 
  - Added SQLite database for sessions and cases
  - Separate authentication database
  - Improved data persistence
- **Web Interface Flow**:
  - Login page as entry point (in production mode)
  - Case Manager as main dashboard
  - Session-based navigation
- **File Organization**:
  - Files now associated with cases
  - Better file tracking and management
  - Case-based data isolation

### Technical Details
- Added `session_db.py` module for database operations
- Added `security_enhancements.py` for security features
- New routes: `/login`, `/signup`, `/case_manager`, `/logout`
- Database tables: `cases`, `sessions`, `chat_messages`, `queries`, `preferences`, `session_files`
- Environment variable `DEV_MODE` for development/production switching

## [2.0.4] - 2024-11-26

### Added
- **ZIP File Support**: Full support for UFDR ZIP file format with automatic extraction
  - Extracts JSON files from `Artifacts/` folder (Calls, Contacts, SMS, WhatsApp)
  - Extracts metadata from `__metadata__/` folder
  - Extracts images from `Media/Images/` folder
  - Extracts videos from `Media/Videos/` folder
  - Automatic normalization to unified UFDR format
- **Images Gallery**: Dedicated Images tab for viewing images from ZIP files
  - Responsive grid layout
  - Click to view full-size images
  - Image count display
  - Automatic detection when ZIP files contain images
- **Multimodal AI Analysis**: Qwen2.5-VL-7B integration for image analysis
  - Analyze images from UFDR files
  - Automatic image query detection
  - Image citations in AI responses
  - Support for 4-bit quantization for lower VRAM usage
- **Direct JSON Extraction**: LLM can now directly extract data from JSON files
  - `use_json` flag for raw JSON processing
  - Smart truncation based on query intent
  - Improved data extraction accuracy
- **Enhanced File Upload UI**: 
  - Shows both JSON and ZIP files in uploaded files list
  - File type badges (JSON/ZIP)
  - File icons for better visual distinction
- **Improved Stats Display**:
  - Images count in stats card (always visible)
  - Fixed file count calculation (excludes metadata)
  - Better ZIP file detection

### Changed
- **Dependencies Updated**:
  - transformers: 4.35.2 → 4.57.3
  - torch: 2.1.0 → 2.9.1
  - torchvision: 0.18.1 → 0.24.1
  - tokenizers: 0.15.2 → 0.22.1
  - accelerate: 0.24.0 → 1.12.0
- **UI Improvements**:
  - Images tab in navigation (appears when images are detected)
  - Consistent dark/light mode across all pages
  - Better file upload feedback
- **Backend Enhancements**:
  - Improved ZIP extraction with better error handling
  - Enhanced media file serving for ZIP-extracted images
  - Better handling of nested UFDR structures

### Fixed
- Fixed file count showing 2 instead of 1 when uploading ZIP files
- Fixed image serving from ZIP extraction paths
- Fixed AttributeError with None values in data extraction
- Fixed UnboundLocalError in streaming endpoint
- Improved error handling for corrupted model downloads
- Fixed image query detection in streaming endpoint

### Technical Details
- Added `/api/images` endpoint for image list retrieval
- Enhanced `/api/media/<path>` endpoint to serve ZIP-extracted images
- Updated `/api/stats` to include image/video counts
- Improved ZIP extraction with proper path handling
- Added automatic model cache clearing for corrupted downloads

## [2.0.2] - 2024-11-23

### Changed
- **Backend Migration**: Switched from Ollama to LM Studio for better AMD GPU support on Windows
- **Performance Optimization**: Optimized for lower-end devices (2GB+ VRAM, 16GB RAM)
  - Reduced conversation history from 10 to 4 messages
  - Limited context size to 3000 characters
  - Reduced max response tokens to 500
  - Optimized prompt structure for efficiency
- **Code Quality**: Replaced print statements with proper logging system
- **Documentation**: Removed outdated Ollama documentation, updated all references to LM Studio

### Added
- **Multilingual Support**: Automatic language detection and response in user's language
- **Enhanced Prompting**: Improved prompt engineering with examples for better AI responses
- **Conversation Memory**: Follow-up question support with conversation history
- **Low VRAM Optimization**: Automatic context truncation and message limiting for weaker devices
- **Proper Logging**: Structured logging system replacing debug print statements

### Removed
- Ollama integration and all related documentation
- Debug print statements (replaced with logging)
- Outdated setup guides referencing Ollama

### Fixed
- Follow-up questions now properly use conversation history
- Improved error handling and logging
- Better memory management for chat histories

## [2.0.1] - 2024

### Added
- Complete forensic analysis system for UFDR files
- AI Chat Assistant with Ollama integration
- Natural language query processing
- Scenario detection (Insider Data Leak, Scam Network, SIM Swap Attack)
- Keyword recognition and pattern matching
- Entity recognition for people and organizations
- Relevance scoring for query results
- Modern web-based interface with dark/light mode
- Comprehensive documentation and setup guides
- Multiple query engine implementations
- RAG (Retrieval-Augmented Generation) engine
- Smart analyzer for forensic insights
- File upload and management system
- Test data for all three scenarios

### Features
- **Core Analysis**: Scenario detection, keyword matching, pattern recognition
- **AI Features**: Chat assistant, semantic search, enhanced analysis
- **Web Interface**: Responsive UI, real-time analysis, interactive queries
- **Documentation**: Complete setup guides, troubleshooting, API documentation

### Setup
- Automated setup scripts (minimal and complete)
- Cross-platform support (Windows, Mac, Linux)
- Comprehensive error handling and validation

---

## Future Releases

### Planned
- [ ] Additional scenario types
- [ ] Enhanced visualization
- [ ] Export functionality improvements
- [ ] Performance optimizations
- [ ] Additional AI model support

---

For detailed information, see [README.md](README.md) and [INSTALLATION.md](INSTALLATION.md).


