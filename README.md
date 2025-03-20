# Security Testing Framework

A modular, agent-based framework for automated security testing that combines OpenAI's Agents SDK with Google's Gemini API for intelligent vulnerability assessment and automated exploitation.

## Overview

This framework combines traditional security testing tools with AI-powered analysis to automate the vulnerability discovery and testing process. It features:

- Automated nmap scanning and service detection
- AI-powered CVE lookup for discovered services
- Intelligent command suggestion based on scan results
- Vulnerability testing with appropriate commands
- Comprehensive reporting and documentation

## Components

### Core Scripts

- **run-example.py**: Main runner script that orchestrates the entire security testing process
- **gemsearch.py**: Wrapper for Gemini API to search for CVEs affecting specific software/services
- **suggest.py**: Generates intelligent security testing command suggestions based on scan results

### Agent System

The framework uses a modular agent-based approach:

- **WatchDog**: Main orchestration agent that manages the overall testing process
- **Nmap Agent**: Handles service discovery and version identification
- **Search Agent**: Looks up vulnerabilities for discovered services using Gemini
- **Command Suggestion Agent**: Recommends appropriate testing commands for vulnerabilities
- **Execution Agent**: Safely executes recommended commands to test for vulnerabilities
- **File System Agent**: Manages the output report generation

## Requirements

- Python 3.7+
- openai-agents
- Google Gemini API key
- Required Python packages:
  - google-generativeai
  - asyncio
  - dataclasses
  - subprocess

## Setup

1. Clone the repository
2. Install required dependencies:
   ```
   pip install google-generativeai
   ```
3. Set your Gemini API key in both `gemsearch.py` and `suggest.py`:
   ```python
   GEMINI_API_KEY = "your_api_key_here"

4. Set OPENAI_API_KEY as enviorment variable
   ```
    export OPENAI_API_KEY = "your_api_key_here"
5. Set GEMINI_API_KEY as enviorment variable
   ```
    export GEMINI_API_KEY = "your_api_key_here"
## Usage

Run the main script with:

```
python run-example.py
```

The framework will:
1. Scan the target IP (192.168.166.115 by default)
2. Identify running services and their versions
3. Search for relevant CVEs affecting those services
4. Generate appropriate testing commands
5. Test for vulnerabilities
6. Create comprehensive reports in the `/pwn` directory

## Output

After execution, results will be stored in:
- `/pwn/scan_results.txt`: Full scan results
- `/pwn/commands_ran.txt`: List of executed commands
- `/pwn/command_outputs.txt`: Command outputs and findings

## Security Notice

This tool is intended for authorized security testing only. Always ensure you have proper permission to test any systems. The framework includes safety measures like:
