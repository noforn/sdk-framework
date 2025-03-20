# WatchDog - Automated Security Testing Framework

Developmental concept for a modular, agent-based framework enabling automated security testing through a combination of OpenAI's Agents SDK and Google's Gemini API for intelligent autonomous vulnerability assessment and exploitation. 

## Disclaimer and Ethical Use Notice

This tool is intended **ONLY** for authorized security testing and educational purposes. Always ensure you have explicit permission to test any systems.

**LEGAL DISCLAIMER:** The developers of this framework are not responsible for any misuse, damage, or illegal activities performed with this developmental concept. Users are solely responsible for ensuring all related activities comply with all applicable laws, regulations, and organizational policies.

**INTENDED USE:**
- Security professionals conducting authorized penetration tests
- Educational environments teaching cybersecurity concepts
- Research and development of defensive security measures
- Organizations seeking to test and harden their security posture

**PROHIBITED USE:**
- Unauthorized testing of any system without explicit written permission
- Any illegal activities or attacks against systems
- Exploitation of vulnerabilities in production environments without proper authorization

By using this framework, you agree to use it responsibly and ethically. Always obtain proper written authorization before testing any system.

Remember, life is more enjoyable when Europol doesn't know your name.

## Overview

This framework combines traditional security testing tools with AI-powered analysis to automate the vulnerability discovery and testing process. It features:

- Automated scanning and service detection
- CVE lookup for discovered services
- Command suggestion from reasoning model based on scan results
- Autonomous testing of discovered vulnerabilities
- Run Stream Context
- Optional RAG implementation
- Comprehensive reporting and documentation

## Components

### Core Scripts

- **run-example.py**: Main runner script that orchestrates the entire security testing process
- **gemsearch.py**: Wrapper for Gemini API to search for CVEs affecting specific services/versions
- **suggest.py**: 'gemini-2.0-flash-thinking-exp-01-21' generates security testing command suggestions based on scan results and discovered vulnerabilities

### Agent System

The framework uses a modular agent-based approach:

- **WatchDog**: Main orchestration agent that manages the overall testing process. Uses other agents as tools. Obtains consent first.
- **Nmap Agent**: Runs nmap for discovery and version identification
- **Search Agent**: Searches for public vulnerabilities related to discovered service versions using Gemini (more cost-efficient compared to OpenAI's WebSearchTool)
- **Command Suggestion Agent**: Reasons and suggets appropriate testing commands based on discovered vulnerabilities
- **Testing Agent**: Uses tools to search for and create POC (proof of concept) examples for discovered vulnerabilities. Aims to create working exploit scripts.
- **Execution Agent**: Executes recommended commands and generated exploit scripts to test exploitation of discovered vulnerabilities
- **File System Agent**: Manages the output report generation and some other file system operations

## Requirements

- Python / UV
- openai-agents
- OpenAI/Gemini API keys
- Required Python packages:
  - google-generativeai
  - openai-agents
  - asyncio

## Setup

1. Install UV
    ```
    curl -LsSf https://astral.sh/uv/install.sh | sh
2. Set up enviorment
    ```
    uv venv --python 3.11
    source .venv/bin/activate
3. Install required dependencies:
   ```
   uv pip install openai-agents
   uv pip install -q -U google-genai
   ```
4. Set your Gemini API key in both `gemsearch.py` and `suggest.py`:
   ```python
   GEMINI_API_KEY = "your_api_key_here"

5. OR Set OPENAI_API_KEY as enviorment variable
   ```
    export OPENAI_API_KEY = "your_api_key_here"
6. Set GEMINI_API_KEY as enviorment variable
   ```
    export GEMINI_API_KEY = "your_api_key_here"
## Usage

Run the main script with:

```
python run-example.py
```

The framework will:
1. Scan the target IP (192.168.1.1 by default)
2. Identify running services and their versions
3. Search for relevant CVEs affecting those services
4. Search for and create relevant POCs
4. Generate and execute applicable commands
5. Test for vulnerabilities
6. Create comprehensive reports in the `/pwn` directory

## Output

After execution, results will be stored in:
- `/pwn/scan_results.txt`: Full scan results
- `/pwn/commands_ran.txt`: List of executed commands
- `/pwn/command_outputs.txt`: Command outputs and findings
This can easily be customized in 'run-example.py'.

## Security Notice

This concept is intended for authorized security testing only. Always ensure you have proper permission to test any systems. The framework includes limited safety measures. Deploy at your own risk within isolated enviorments.
