import asyncio
import random
import os
import sys
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Set
from agents import Agent, ItemHelpers, Runner, function_tool, RunContextWrapper, handoff, trace, WebSearchTool, ModelSettings
from google import genai
from google.genai.types import GenerateContentConfig, FunctionDeclaration, Tool, ToolConfig
## Context

@dataclass
class SecurityTestContext:
    """Context to maintain state between retries"""
    completed_steps: Set[str] = field(default_factory=set)
    nmap_results: Optional[str] = None
    web_search_results: Optional[str] = None
    last_tool_name: Optional[str] = None
    target_ip: str = "192.168.150.35"

# Gemini Tools

@function_tool
def gemini_search(query: str) -> str:
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, "gemsearch.py", query],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error performing Gemini search: {e.stderr}\n\nFalling back to standard web search..."
    except Exception as e:
        return f"Error: {str(e)}\n\nFalling back to standard web search..."
    
@function_tool
def suggest_commands(scan_results: str, vulnerabilities: str, target_ip: str) -> str:
    if not scan_results or not vulnerabilities or not target_ip:
        missing = []
        if not scan_results: missing.append("scan_results")
        if not vulnerabilities: missing.append("vulnerabilities")
        if not target_ip: missing.append("target_ip")
        return f"Error: Missing required parameters: {', '.join(missing)}. All three parameters must be provided."
    import subprocess
    import json
    
    try:
        # context for suggestions
        context = {
            "scan_results": scan_results,
            "vulnerabilities": vulnerabilities,
            "target_ip": target_ip,
            "prior_commands": "curl --max-time 10 -I http://{}".format(target_ip)
        }
        
        # context to json
        context_json = json.dumps(context)
        
        # call suggest script
        result = subprocess.run(
            [sys.executable, "suggest.py", context_json],
            capture_output=True,
            text=True,
            check=True
        )
        
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error getting command suggestions: {e.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"
    
@function_tool
def search_exploit_poc(cve_id: str, service_version: str) -> str:
    """Search for proof-of-concept exploit code for a specific CVE"""
    try:
        query = f"{cve_id} exploit-db {service_version} proof-of-concept"
        result = subprocess.run(
            [sys.executable, "gemsearch.py", query],
            capture_output=True,
            text=True,
            check=True
        )
        search_results = result.stdout.strip()
        return f"""
        Search results for {cve_id}:
        {search_results}
        """
    except Exception as e:
        return f"Error searching for exploit POC: {str(e)}"

# Standard tools

@function_tool
def run_whoami() -> str:
    result = subprocess.check_output(['whoami'], text=True).strip()
    return result

@function_tool
def run_nmap(ip_addess: str) -> str:
    result = subprocess.check_output(['nmap', '-sV', ip_addess], text=True).strip()
    return result

@function_tool
def execute_command(command_string: str) -> str:
    try:
        print(f"[EXECUTE] I'm running: {command_string}")
        result = subprocess.check_output(command_string, shell=True, text=True, stderr=subprocess.STDOUT)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error executing {command_string}: {e.output}"
    
@function_tool
def list_files(directory: str) -> str:
    try:
        dir_to_list = directory if directory else "."
        items = os.listdir(dir_to_list)
        files = []
        directories = []
        
        for item in items:
            full_path = os.path.join(dir_to_list, item)
            if os.path.isdir(full_path):
                directories.append(f"📁 {item}/")
            else:
                files.append(f"📄 {item}")
        
        result = f"Contents of {dir_to_list}:\n\nDirectories:\n" + "\n".join(directories) + "\n\nFiles:\n" + "\n".join(files)
        return result
    except Exception as e:
        return f"Error listing files: {str(e)}"

@function_tool
def read_file(filepath: str) -> str:
    try:
        with open(filepath, 'r') as file:
            content = file.read()
        return content
    except Exception as e:
        return f"Error reading file: {str(e)}"

@function_tool
def write_file(filepath: str, content: str) -> str:
    try:
        with open(filepath, 'w') as file:
            file.write(content)
        return f"Successfully wrote to {filepath}"
    except Exception as e:
        return f"Error writing to file: {str(e)}"
    
@function_tool
def create_exploit_file(filename: str, content: str) -> str:
    """Create a file with exploit code"""
    try:
        # Ensure the /pwn/exploits directory exists
        os.makedirs("~/pwn/exploits", exist_ok=True)
        
        # Create the full path
        filepath = os.path.join("/pwn/exploits", filename)
        
        # Write the content to the file
        with open(filepath, 'w') as f:
            f.write(content)
        
        # Set executable permissions if it looks like a script
        if filename.endswith(('.py', '.sh', '.pl', '.rb')):
            os.chmod(filepath, 0o755)
        
        return f"Successfully created exploit file {filepath}"
    except Exception as e:
        return f"Error creating exploit file: {str(e)}"
    
# Specialized Agents

file_system_agent = Agent(
    name="File System Agent",
    instructions="Execute file operations using only the provided tools: list_files, read_file, and write_file. Do not attempt to use shell commands. For write_file, directly create or overwrite files without asking for confirmation. For directory creation, first check if directory exists, then write a file inside it. Report only success or errors.",
    tools=[list_files, read_file, write_file],
)

whoami_agent = Agent(
    name="whoami Agent",
    instructions="Call the 'run_whoami' tool and return the exact result without additional commentary.",
    tools=[run_whoami],
)

search_agent = Agent(
    name="Search Agent",
    instructions="Search for and return valid CVEs affecting the exact service versions specified. Rank results by severity (highest first). Format output as numbered list with CVE ID, severity, and brief description. Omit mitigation advice.",
    tools=[gemini_search],
)

nmap_agent = Agent(
    name="Nmap Agent",
    instructions="Scan the IP address using run_nmap tool. Extract and format results in a structured format showing each service, port, and complete version information. Return this information in a simple, nice looking output.",
    tools=[run_nmap]
)

exec_agent = Agent(
    name="Execution Agent",
    instructions=(
        "Execute commands to test vulnerabilities using execute_command tool. "
        "Select commands that target specific vulnerabilities from previous findings. "
        "Use bash one-liners when possible for simulating exploits. "
        "Avoid interactive tools. Return only the command output."
        "Always include the target IP, never use example targets or other IPs"
    ),
    tools=[execute_command]
)

suggest_agent = Agent(
    name="Command Suggestion Agent",
    instructions="Suggest improved security testing commands based on scan results and discovered vulnerabilities. Always provide the target_ip, scan_results, and vulnerabilities parameters when calling this tool.",
    tools=[suggest_commands],
)

testing_agent = Agent(
    name="Exploit Agent",
    instructions=(
        "You are an agent specialized in finding and deploying exploit code. "
        "Follow these steps when asked to exploit a vulnerability:\n"
        "1. Use search_exploit_poc to search for POC code for the specified CVE\n"
        "2. Create an exploit file in /pwn/exploits/ with the code\n"
        "3. Verify the exploit is tailored to work against the target\n"
        "Always verify exploits before execution."
    ),
    tools=[search_exploit_poc, create_exploit_file, read_file, write_file],
)

## WatchDog Agent with AgentasTools

WatchDog = Agent(
    name="WatchDog",
    instructions=(
            "You are an offensive security testing agent. Complete these tasks in order, using exactly 10 or fewer turns:"
            "1. Use nmap_tool to scan the target IP and identify services/versions"
            "2. If not done previously, use web_search_tool to find CVEs for the EXACT service versions found" 
            "3. Use suggestion_tool to get better commands for testing vulnerabilities by providing ALL THREE parameters:"
            "   - scan_results: The COMPLETE output from the nmap scan"
            "   - vulnerabilities: The COMPLETE list of CVEs from the search results"
            "   - target_ip: The IP address being tested"   
            "4. Select the highest severity vulnerability and investigate if the system is vulnerable"
            "5. For the highest severity vulnerability, use testing_tool to:"
            "   a. Find a POC exploit for the vulnerability"
            "   b. Create an exploit file from the code"
            "   c. Execute the exploit against the target"
            "6. Document everything with these EXACT commands:"
            "   - exec_tool({\"input\": \"mkdir -p /pwn\"})"
            "   - exec_tool({\"input\": \"echo 'SCAN RESULTS:\\n[paste full scan]' > /pwn/scan_results.txt\"})"
            "   - exec_tool({\"input\": \"echo 'COMMANDS:\\n[list commands run]' > /pwn/commands_ran.txt\"})"
            "   - exec_tool({\"input\": \"echo 'OUTPUTS:\\n[paste outputs]' > /pwn/command_outputs.txt\"})"
            "IMPORTANT: Never ask for clarification. Never use example commands. Only run commands that are valid on kali linux systems. If a previous command failed, simply it and try again until it works."
            "Do all file operations with exec_tool. When testing for vulnerabilities, use real commands that would actually check if a vulnerability exists - don't just pretend to test by printing messages."
            "Safety guidelines:"
            "- Always add timeouts to commands that might hang (e.g., curl --max-time 10)"
            "- Never run commands that establish persistent connections without proper termination"
            "- Avoid interactive tools or commands that require user input"
            "- Use non-blocking or asynchronous methods when possible"
            "- Keep command complexity reasonable - prefer simple, targeted checks"
    ),
    tools=[
        whoami_agent.as_tool(
            tool_name="whoami_tool",
            tool_description="Run 'whoami' on the local system.",
        ),
        search_agent.as_tool(
            tool_name="gemini_search_tool",
            tool_description="Search the internet for exploit information relevant to identified service versions.",
        ),
        nmap_agent.as_tool(
            tool_name="nmap_tool",
            tool_description="Run an nmap scan on the given IP.",
        ),
        exec_agent.as_tool(
            tool_name="exec_tool",
            tool_description="Execute commands to assist the user or manage files.",
        ),
        suggest_agent.as_tool(
            tool_name="suggestion_tool",
            tool_description="Get suggested commands for testing discovered vulnerabilities.",
        ),
        testing_agent.as_tool(
            tool_name="testing_tool",
            tool_description="Find and deploy exploit code."
        )
    ],
    model_settings=ModelSettings(tool_choice="auto"),
)

## Run Stream

async def main():
    max_retries = 3
    retry_count = 0
    backoff_base = 2
    
    context = SecurityTestContext()
    
    print("=== Run Starting ===")
    
    while retry_count < max_retries:
        try:
            input_text = "run a scan on 192.168.150.35. search for exploits on these services. finally, use exec_tool to test for one of the discovered vulnerabilities"
            
            if retry_count > 0:
                if "nmap_scan" in context.completed_steps and "web_search" in context.completed_steps:
                    # If done scan + search, test vulnerabilities
                    input_text = (
                        "I've already scanned 192.168.166.115 and searched for exploits. "
                        "Continue testing one of the vulnerabilities without repeating previous steps. "
                        f"Here's what we know:\n\nScan results: {context.nmap_results}\n\n"
                        f"Vulnerability search results: {context.web_search_results}"
                    )
                elif "nmap_scan" in context.completed_steps:
                    # If done scan but not search
                    input_text = (
                        "I've already scanned 192.168.166.115. "
                        f"Here are the scan results: {context.nmap_results}\n\n"
                        "Continue by searching for exploits and then testing vulnerabilities."
                    )
            
            result = Runner.run_streamed(
                WatchDog,
                input=input_text,
                context=context
            )
            
            async for event in result.stream_events():
                if event.type == "agent_updated_stream_event":
                    print(f"Agent Updated: {event.new_agent.name}")
                    
                elif event.type == "run_item_stream_event":
                    if event.item.type == "tool_call_item":
                        if hasattr(event.item.raw_item, 'name'):
                            tool_name = event.item.raw_item.name
                            context.last_tool_name = tool_name
                            
                            if tool_name == "nmap_tool":
                                print("-- Nmap Scan Initialized")
                            elif tool_name == "web_search_tool":
                                print("-- Web Search Initialized")
                            elif tool_name == "exec_tool":
                                print("-- Command Execution Initialized")
                            else:
                                print(f"-- Tool Called: {tool_name}")
                        else:
                            print("-- Tool was called")
                            
                    elif event.item.type == "tool_call_output_item":
                        print(f"-- Tool Output: {event.item.output}")
                        
                        # Save results in context for potential retries
                        if context.last_tool_name == "nmap_tool":
                            context.nmap_results = event.item.output
                            context.completed_steps.add("nmap_scan")
                        elif context.last_tool_name == "web_search_tool":
                            context.web_search_results = event.item.output
                            context.completed_steps.add("web_search")
                            
                    elif event.item.type == "message_output_item":
                        print(f"Message output:\n{ItemHelpers.text_message_output(event.item)}")
            
            print("=== Run Complete ===")
            break
            
        except Exception as e:
            error_name = type(e).__name__
            print(f"Error during execution ({error_name}): {str(e)}")
            
            retry_count += 1
            if retry_count < max_retries:
                backoff_time = backoff_base ** retry_count
                print(f"Retrying in {backoff_time} seconds ({retry_count}/{max_retries})...")
                await asyncio.sleep(backoff_time)
                # context for next iteration
            else:
                print("Max retries reached, exiting.")
                break
    
    if retry_count >= max_retries:
        print("Operation failed after maximum retry attempts.")


if __name__ == "__main__":
    asyncio.run(main())