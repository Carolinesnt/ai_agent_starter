#!/usr/bin/env python3
"""
BYE BAC - Broken Access Control Detection CLI
Interactive command-line interface for AI-powered security testing agent
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Display BYE BAC ASCII banner"""
    banner = f"""{Colors.OKCYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██████╗ ██╗   ██╗███████╗    ██████╗  █████╗  ██████╗      ║
    ║   ██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗██╔════╝      ║
    ║   ██████╔╝ ╚████╔╝ █████╗      ██████╔╝███████║██║           ║
    ║   ██╔══██╗  ╚██╔╝  ██╔══╝      ██╔══██╗██╔══██║██║           ║
    ║   ██████╔╝   ██║   ███████╗    ██████╔╝██║  ██║╚██████╗      ║
    ║   ╚═════╝    ╚═╝   ╚══════╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ║
    ║                                                              ║
    ║        🔒 Broken Access Control Detection Agent 🤖           ║
    ║                                                              ║
    ║    AI-Powered Security Testing for RBAC APIs                 ║
    ║    Version 1.0.0 | Made with ❤️  for Secure APIs              ║ 
    ╚══════════════════════════════════════════════════════════════╝
    {Colors.ENDC}"""
    print(banner)

def show_help():
    """Display simple help menu"""
    print_banner()
    help_text = f"""
{Colors.BOLD}{Colors.OKGREEN}QUICK START:{Colors.ENDC}
  1. Run {Colors.OKCYAN}byebac /check{Colors.ENDC} to verify setup
  2. Run {Colors.OKCYAN}byebac /runagent{Colors.ENDC} to start testing
  3. Run {Colors.OKCYAN}byebac /report{Colors.ENDC} to view results

{Colors.BOLD}{Colors.OKGREEN}AVAILABLE COMMANDS:{Colors.ENDC}
  {Colors.OKCYAN}byebac /check{Colors.ENDC}        - Validate setup and dependencies
  {Colors.OKCYAN}byebac /runagent{Colors.ENDC}     - Execute AI security testing agent
  {Colors.OKCYAN}byebac /status{Colors.ENDC}       - Show recent test run status
  {Colors.OKCYAN}byebac /report{Colors.ENDC}       - Open test report (latest or by date)
  {Colors.OKCYAN}byebac /config{Colors.ENDC}       - Display current configuration
  {Colors.OKCYAN}byebac /clean{Colors.ENDC}        - Clean all artifacts and old reports
  {Colors.OKCYAN}byebac /specification{Colors.ENDC} - Show technical specifications
  {Colors.OKCYAN}byebac /information{Colors.ENDC}  - Interactive command information guide

{Colors.BOLD}TIP:{Colors.ENDC} Run {Colors.OKCYAN}byebac /information{Colors.ENDC} for detailed explanations of each command
    """
    print(help_text)

def show_information():
    """Interactive command information guide with back navigation"""
    commands = {
        '1': {
            'name': '/check',
            'title': '🔍 Check Setup & Dependencies',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Validates your BYE BAC installation and verifies all required components
  are properly configured before running security tests.

{Colors.BOLD}What it checks:{Colors.ENDC}
  ✓ Python version and environment
  ✓ Required configuration files (agent.yaml, policy.yaml, auth.yaml)
  ✓ OpenAPI specification file
  ✓ Python dependencies (yaml, openai, requests, jinja2)
  ✓ Core agent scripts availability

{Colors.BOLD}When to use:{Colors.ENDC}
  • First time setup - verify everything is installed correctly
  • Troubleshooting - diagnose missing dependencies or config files
  • After updates - ensure new components are properly configured

{Colors.BOLD}Example usage:{Colors.ENDC}
  {Colors.OKCYAN}byebac /check{Colors.ENDC}

{Colors.BOLD}Output:{Colors.ENDC}
  Displays a checklist with ✓ (success) or ✗ (failure) for each component.
  If anything fails, install missing items with: pip install -r requirements.txt
            """
        },
        '2': {
            'name': '/runagent',
            'title': '🚀 Run AI Security Testing Agent',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Executes the main BYE BAC agent to perform automated security testing
  on your API using AI-powered test case generation.

{Colors.BOLD}What it does:{Colors.ENDC}
  1. Reads OpenAPI specification to understand your API endpoints
  2. Loads RBAC policies from policy.yaml
  3. Uses LLM (GPT-4) to generate intelligent test cases
  4. Tests for BOLA, IDOR, privilege escalation vulnerabilities
  5. Generates comprehensive JSON and HTML reports

{Colors.BOLD}Requirements:{Colors.ENDC}
  • Valid OpenAPI spec in ai_agent/data/openapi.json
  • RBAC policies defined in ai_agent/config/policy.yaml
  • API credentials in ai_agent/config/auth.yaml
  • OpenAI API key configured (for LLM access)

{Colors.BOLD}When to use:{Colors.ENDC}
  • Running scheduled security scans
  • Testing after API changes or updates
  • Validating RBAC implementation
  • Before production deployments

{Colors.BOLD}Example usage:{Colors.ENDC}
  {Colors.OKCYAN}byebac /runagent{Colors.ENDC}

{Colors.BOLD}Output:{Colors.ENDC}
  • Real-time console output showing test progress
  • JSON report: ai_agent/runs/report-YYYYMMDD-HHMMSS.json
  • HTML report: ai_agent/runs/report-YYYYMMDD-HHMMSS.html
  • Test artifacts in ai_agent/runs/artifacts/

{Colors.BOLD}Duration:{Colors.ENDC}
  Typically 2-5 minutes depending on API size and number of endpoints.
            """
        },
        '3': {
            'name': '/status',
            'title': '📊 View Test Run Status',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Displays a summary of your most recent test run results without
  opening the full report.

{Colors.BOLD}What it shows:{Colors.ENDC}
  • Latest report filename and timestamp
  • Total number of tests executed
  • Test execution duration
  • Roles tested (e.g., Employee, Admin_HC)
  • Confusion matrix (TP, TN, FP, FN counts)
  • Number of potential vulnerabilities found

{Colors.BOLD}When to use:{Colors.ENDC}
  • Quick check after running tests
  • Monitoring test results over time
  • Verifying tests completed successfully

{Colors.BOLD}Example usage:{Colors.ENDC}
  {Colors.OKCYAN}byebac /status{Colors.ENDC}

{Colors.BOLD}Output:{Colors.ENDC}
  Quick summary with key metrics like:
  - Total Tests: 67
  - Duration: 167.7s
  - True Negatives: 48, False Positives: 5, False Negatives: 5
  - Potential Vulnerabilities: 5
            """
        },
        '4': {
            'name': '/report',
            'title': '📄 Open Test Report',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Displays the location of test reports (JSON and HTML) for detailed
  analysis of security findings.

{Colors.BOLD}Usage modes:{Colors.ENDC}
  1. {Colors.OKCYAN}byebac /report{Colors.ENDC}         - Shows latest report
  2. {Colors.OKCYAN}byebac /report 20251022-122657{Colors.ENDC} - Specific date/time report

{Colors.BOLD}What it shows:{Colors.ENDC}
  • Path to JSON report (machine-readable, detailed)
  • Path to HTML report (human-readable, interactive dashboard)
  • Report metadata (timestamp, file size)

{Colors.BOLD}When to use:{Colors.ENDC}
  • After running tests to view detailed findings
  • Reviewing historical test results
  • Sharing reports with team or stakeholders
  • Compliance and audit documentation

{Colors.BOLD}Report contents:{Colors.ENDC}
  • Executive summary with metrics
  • Detailed vulnerability findings
  • Test case results (pass/fail/error)
  • Confusion matrix and accuracy stats
  • Request/response evidence for each finding

{Colors.BOLD}Tip:{Colors.ENDC}
  Open HTML report in browser for best visualization and filtering.
            """
        },
        '5': {
            'name': '/config',
            'title': '⚙️  View Configuration',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Displays current agent configuration and RBAC policy settings
  to help you understand what will be tested.

{Colors.BOLD}What it shows:{Colors.ENDC}
  • Agent configuration (agent.yaml) - first 15 lines
  • Policy configuration (policy.yaml) - first 15 lines
  • File paths for full configuration access

{Colors.BOLD}Configuration files explained:{Colors.ENDC}
  📄 {Colors.OKCYAN}agent.yaml{Colors.ENDC}  - Agent behavior, LLM settings, test strategy
  📄 {Colors.OKCYAN}policy.yaml{Colors.ENDC} - RBAC rules defining who can access what
  📄 {Colors.OKCYAN}auth.yaml{Colors.ENDC}   - API credentials for different roles

{Colors.BOLD}When to use:{Colors.ENDC}
  • Verify which endpoints/roles are configured for testing
  • Check RBAC policy rules before running tests
  • Troubleshoot unexpected test results
  • Understanding test coverage scope

{Colors.BOLD}Example usage:{Colors.ENDC}
  {Colors.OKCYAN}byebac /config{Colors.ENDC}

{Colors.BOLD}Note:{Colors.ENDC}
  Only shows preview (15 lines). Edit full files in ai_agent/config/
  for complete configuration management.
            """
        },
        '6': {
            'name': '/specification',
            'title': '📋 Technical Specifications',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Provides comprehensive technical documentation about the BYE BAC
  agent architecture, capabilities, and configuration.

{Colors.BOLD}Information included:{Colors.ENDC}
  • {Colors.OKCYAN}LLM Configuration{Colors.ENDC} - Model details, token limits, temperature
  • {Colors.OKCYAN}Agent Architecture{Colors.ENDC} - Multi-agent system components
  • {Colors.OKCYAN}Vulnerability Types{Colors.ENDC} - BOLA, IDOR, BAC, etc.
  • {Colors.OKCYAN}Testing Capabilities{Colors.ENDC} - Baseline, mutation, policy-based
  • {Colors.OKCYAN}Configuration Files{Colors.ENDC} - Purpose of each config file
  • {Colors.OKCYAN}Output Formats{Colors.ENDC} - JSON, HTML, CSV reporting
  • {Colors.OKCYAN}Performance Metrics{Colors.ENDC} - Speed, coverage, accuracy
  • {Colors.OKCYAN}Best Practices{Colors.ENDC} - Recommended usage guidelines

{Colors.BOLD}When to use:{Colors.ENDC}
  • Understanding how the agent works internally
  • Learning about supported vulnerability types
  • Configuring LLM settings for your needs
  • Reference for documentation or presentations

{Colors.BOLD}Example usage:{Colors.ENDC}
  {Colors.OKCYAN}byebac /specification{Colors.ENDC}

{Colors.BOLD}Audience:{Colors.ENDC}
  Security engineers, developers, and technical stakeholders who need
  deep understanding of the agent's capabilities and architecture.
            """
        },
        '7': {
            'name': '/clean',
            'title': '🧹 Clean Artifacts & Reports',
            'description': f"""
{Colors.BOLD}Purpose:{Colors.ENDC}
  Deletes all test artifacts and old reports to free up disk space
  and prepare for fresh testing runs.

{Colors.BOLD}What gets deleted:{Colors.ENDC}
  • {Colors.OKCYAN}Test Artifacts{Colors.ENDC} - All JSON request/response files
  • {Colors.OKCYAN}Report Files{Colors.ENDC} - All report-*.json and report-*.md files
  • {Colors.OKCYAN}Empty Directories{Colors.ENDC} - Role-based artifact folders
  • {Colors.OKCYAN}Preserves{Colors.ENDC} - Configuration files and source code

{Colors.BOLD}Safety features:{Colors.ENDC}
  ✓ Shows file count and total size before deletion
  ✓ Requires explicit confirmation (yes/no)
  ✓ Only deletes test data, never config or code
  ✓ Can be cancelled at any time

{Colors.BOLD}When to use:{Colors.ENDC}
  • Before starting a new test campaign - fresh baseline
  • After completing a test cycle - cleanup old data
  • Low disk space - artifacts can grow large over time
  • Preparing for deployment - remove test data

{Colors.BOLD}Example usage:{Colors.ENDC}
  {Colors.OKCYAN}byebac /clean{Colors.ENDC}

{Colors.BOLD}Output:{Colors.ENDC}
  Shows summary of files to delete, asks for confirmation, then
  displays progress and final count of deleted files + space freed.

{Colors.WARNING}⚠️  Warning:{Colors.ENDC}
  This action is irreversible! Make sure to backup any reports you
  want to keep before running cleanup.
            """
        }
    }
    
    while True:
        print_banner()
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}📖 COMMAND INFORMATION GUIDE{Colors.ENDC}\n")
        print(f"{Colors.BOLD}Select a command to learn more:{Colors.ENDC}\n")
        
        for key, cmd in commands.items():
            print(f"  {Colors.OKCYAN}[{key}]{Colors.ENDC} {cmd['title']}")
        
        print(f"\n  {Colors.WARNING}[0]{Colors.ENDC} Back to main menu")
        print(f"\n{Colors.BOLD}Enter your choice (0-7):{Colors.ENDC} ", end='')
        
        try:
            choice = input().strip()
            
            if choice == '0':
                # Go back - show help
                show_help()
                break
            elif choice in commands:
                # Show detailed info
                cmd = commands[choice]
                print_banner()
                print(f"\n{Colors.BOLD}{Colors.OKGREEN}{cmd['title']}{Colors.ENDC}")
                print(f"{Colors.BOLD}Command:{Colors.ENDC} {Colors.OKCYAN}byebac {cmd['name']}{Colors.ENDC}")
                print(cmd['description'])
                print(f"\n{Colors.WARNING}Press Enter to go back...{Colors.ENDC}", end='')
                input()
                # Loop continues - show menu again
            else:
                print(f"{Colors.FAIL}Invalid choice. Please enter 0-7.{Colors.ENDC}")
                input(f"{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.WARNING}Exiting information guide.{Colors.ENDC}\n")
            break

def show_specification():
    """Display technical specifications"""
    print_banner()
    spec_text = f"""
{Colors.BOLD}{Colors.OKGREEN}🤖 AI AGENT SPECIFICATIONS{Colors.ENDC}

{Colors.BOLD}{Colors.OKCYAN}LLM Configuration:{Colors.ENDC}
  • Model Provider: OpenAI / Azure OpenAI
  • Primary Model: GPT-4 Turbo (gpt-4-1106-preview)
  • Fallback Model: GPT-3.5 Turbo
  • Temperature: 0.7 (optimal for security testing)
  • Max Tokens: 4096
  • Context Window: 128K tokens

{Colors.BOLD}{Colors.OKCYAN}Agent Architecture:{Colors.ENDC}
  • Core Engine: Multi-Agent Orchestrator
  • Planning Agent: Test case generation & strategy
  • Tester Agent: Execution & validation
  • Triager Agent: Result analysis & classification
  • Memory System: Conversation & test history tracking

{Colors.BOLD}{Colors.OKCYAN}Vulnerability Detection:{Colors.ENDC}
  ✓ BOLA (Broken Object Level Authorization)
  ✓ IDOR (Insecure Direct Object Reference)
  ✓ Vertical Privilege Escalation
  ✓ Horizontal Privilege Escalation
  ✓ Missing Function Level Access Control
  ✓ Authentication Bypass
  ✓ Broken Access Control (BAC)

{Colors.BOLD}{Colors.OKCYAN}Testing Capabilities:{Colors.ENDC}
  • Policy-Based Testing: Uses RBAC policy definitions
  • Baseline Testing: Normal authorized access validation
  • Mutation Testing: Attack scenario generation
  • Automated Authentication: Token management per role
  • Smart Payload Generation: Context-aware test data

{Colors.BOLD}{Colors.OKCYAN}Configuration Files:{Colors.ENDC}
  📄 ai_agent/config/agent.yaml      - Agent behavior settings
  📄 ai_agent/config/policy.yaml     - RBAC policy rules
  📄 ai_agent/config/auth.yaml       - Authentication credentials
  📄 ai_agent/data/openapi.json      - API specification

{Colors.BOLD}{Colors.OKCYAN}Output Formats:{Colors.ENDC}
  • JSON Report: Detailed test results with evidence
  • HTML Report: Interactive web-based dashboard
  • CSV Export: Vulnerability matrix
  • Console Logs: Real-time execution monitoring

{Colors.BOLD}{Colors.OKCYAN}Performance:{Colors.ENDC}
  • Average Speed: 64x faster than manual testing
  • Coverage: Up to 100% endpoint coverage
  • Accuracy: ~83% with low false positive rate
  • Parallel Execution: Concurrent test execution

{Colors.BOLD}{Colors.OKCYAN}Best Practices:{Colors.ENDC}
  ✓ Keep OpenAPI spec up-to-date with API changes
  ✓ Define comprehensive RBAC policies in policy.yaml
  ✓ Use environment variables for sensitive credentials
  ✓ Review false positives to improve policy accuracy
  ✓ Run tests in staging/test environment first
  ✓ Archive reports for compliance & auditing
    """
    print(spec_text)

def check_setup():
    """Validate setup and dependencies"""
    print_banner()
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}🔍 Checking BYE BAC Setup...{Colors.ENDC}\n")
    
    base_dir = Path(__file__).parent
    checks = []
    
    # Check Python version
    python_version = sys.version.split()[0]
    checks.append(("Python Version", python_version, True))
    
    # Check required files
    required_files = [
        ("OpenAPI Spec", base_dir / "ai_agent/data/openapi.json"),
        ("Agent Config", base_dir / "ai_agent/config/agent.yaml"),
        ("Policy Config", base_dir / "ai_agent/config/policy.yaml"),
        ("Auth Config", base_dir / "ai_agent/config/auth.yaml"),
    ]
    
    for name, filepath in required_files:
        exists = filepath.exists()
        checks.append((name, str(filepath.name), exists))
    
    # Check scripts
    scripts_dir = base_dir / "ai_agent/scripts"
    run_agent = scripts_dir / "run_agent.py"
    checks.append(("Run Agent Script", str(run_agent.name), run_agent.exists()))
    
    # Display results
    for name, value, status in checks:
        icon = f"{Colors.OKGREEN}✓{Colors.ENDC}" if status else f"{Colors.FAIL}✗{Colors.ENDC}"
        print(f"  {icon} {name}: {Colors.OKCYAN}{value}{Colors.ENDC}")
    
    # Try to import required modules
    print(f"\n{Colors.BOLD}Python Dependencies:{Colors.ENDC}")
    required_modules = ['yaml', 'openai', 'requests', 'jinja2']
    all_ok = True
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {module}")
        except ImportError:
            print(f"  {Colors.FAIL}✗{Colors.ENDC} {module} (not installed)")
            all_ok = False
    
    if all_ok:
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}✅ Setup is complete! Ready to run.{Colors.ENDC}")
    else:
        print(f"\n{Colors.BOLD}{Colors.WARNING}⚠️  Please install missing dependencies:{Colors.ENDC}")
        print(f"   {Colors.OKCYAN}pip install -r requirements.txt{Colors.ENDC}")

def show_config():
    """Display current configuration"""
    print_banner()
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}⚙️  Current Configuration{Colors.ENDC}\n")
    
    base_dir = Path(__file__).parent
    
    # Show agent.yaml snippet
    agent_config = base_dir / "ai_agent/config/agent.yaml"
    if agent_config.exists():
        print(f"{Colors.BOLD}Agent Configuration:{Colors.ENDC} {Colors.OKCYAN}{agent_config}{Colors.ENDC}")
        with open(agent_config, 'r', encoding='utf-8') as f:
            lines = f.readlines()[:15]  # Show first 15 lines
            for line in lines:
                print(f"  {line.rstrip()}")
        print(f"  {Colors.WARNING}... (truncated, see full file for details){Colors.ENDC}\n")
    
    # Show policy.yaml snippet
    policy_config = base_dir / "ai_agent/config/policy.yaml"
    if policy_config.exists():
        print(f"{Colors.BOLD}Policy Configuration:{Colors.ENDC} {Colors.OKCYAN}{policy_config}{Colors.ENDC}")
        with open(policy_config, 'r', encoding='utf-8') as f:
            lines = f.readlines()[:15]
            for line in lines:
                print(f"  {line.rstrip()}")
        print(f"  {Colors.WARNING}... (truncated, see full file for details){Colors.ENDC}\n")

def show_status():
    """Show recent test runs status"""
    print_banner()
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}📊 Test Run Status{Colors.ENDC}\n")
    
    base_dir = Path(__file__).parent
    runs_dir = base_dir / "ai_agent/runs"
    
    # Find latest report (support both old and new naming formats)
    report_files = (
        list(runs_dir.glob("report-*.json")) + 
        list(runs_dir.glob("BAC_Security_Test_Report-*.json"))
    )
    
    if not report_files:
        print(f"{Colors.WARNING}No test reports found.{Colors.ENDC}")
        print(f"Run {Colors.OKCYAN}byebac /runagent{Colors.ENDC} to generate your first report.\n")
        return
    
    # Sort by modification time
    latest_report = max(report_files, key=lambda p: p.stat().st_mtime)
    
    print(f"{Colors.BOLD}Latest Report:{Colors.ENDC} {Colors.OKCYAN}{latest_report.name}{Colors.ENDC}")
    print(f"{Colors.BOLD}Modified:{Colors.ENDC} {datetime.fromtimestamp(latest_report.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Try to parse and show summary
    try:
        import json
        with open(latest_report, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Read from new report structure
        summary = data.get('summary', {})
        coverage = data.get('coverage', {})
        time_to_detect = data.get('time_to_detect', {})
        confusion = data.get('confusion', {})
        metrics = data.get('metrics', {})
        
        print(f"{Colors.BOLD}Test Summary:{Colors.ENDC}")
        print(f"  Total Tests: {Colors.OKCYAN}{summary.get('total_tests', 'N/A')}{Colors.ENDC}")
        
        # Calculate duration
        duration = time_to_detect.get('seconds', 0)
        duration_str = f"{duration:.1f}s" if duration else "N/A"
        print(f"  Duration: {Colors.OKCYAN}{duration_str}{Colors.ENDC}")
        
        # Show roles tested
        roles_tested = coverage.get('roles', 'N/A')
        print(f"  Roles Tested: {Colors.OKCYAN}{roles_tested}{Colors.ENDC}")
        
        # Show coverage
        coverage_pct = coverage.get('coverage_pct', 0)
        print(f"  Coverage: {Colors.OKCYAN}{coverage_pct}%{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}Confusion Matrix:{Colors.ENDC}")
        print(f"  True Positives (TP): {Colors.OKGREEN}{confusion.get('TP', 0)}{Colors.ENDC}")
        print(f"  True Negatives (TN): {Colors.OKGREEN}{confusion.get('TN', 0)}{Colors.ENDC}")
        print(f"  False Positives (FP): {Colors.WARNING}{confusion.get('FP', 0)}{Colors.ENDC}")
        print(f"  False Negatives (FN): {Colors.FAIL}{confusion.get('FN', 0)}{Colors.ENDC}")
        print(f"  Errors (ERR): {Colors.FAIL}{confusion.get('ERR', 0)}{Colors.ENDC}")
        print(f"  Not Found (NF): {Colors.WARNING}{confusion.get('NF', 0)}{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}Metrics:{Colors.ENDC}")
        print(f"  Precision: {Colors.OKCYAN}{metrics.get('precision', 0):.2%}{Colors.ENDC}")
        print(f"  Recall: {Colors.OKCYAN}{metrics.get('recall', 0):.2%}{Colors.ENDC}")
        print(f"  F1-Score: {Colors.OKCYAN}{metrics.get('f1', 0):.3f}{Colors.ENDC}")
        print(f"  Accuracy: {Colors.OKCYAN}{metrics.get('accuracy', 0):.2%}{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}Vulnerabilities:{Colors.ENDC}")
        print(f"  Potential Issues Found: {Colors.FAIL}{summary.get('potential_vulnerabilities', 0)}{Colors.ENDC}")
        
        # Show LLM summary preview if available
        llm_summary = data.get('llm_summary', '')
        if llm_summary and not llm_summary.startswith('⚠️'):
            print(f"\n{Colors.BOLD}LLM Summary (Preview):{Colors.ENDC}")
            # Show first 6 lines of summary
            summary_lines = llm_summary.strip().split('\n')[:6]
            for line in summary_lines:
                print(f"  {line}")
            if len(llm_summary.split('\n')) > 6:
                print(f"  {Colors.WARNING}... (see full report for complete summary){Colors.ENDC}")
        
    except Exception as e:
        print(f"{Colors.WARNING}Could not parse report: {e}{Colors.ENDC}")
    
    print()

def run_agent():
    """Execute the AI agent"""
    print_banner()
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}🚀 Starting BYE BAC Agent...{Colors.ENDC}\n")
    
    base_dir = Path(__file__).parent
    script_path = base_dir / "ai_agent/scripts/run_agent.py"
    
    if not script_path.exists():
        print(f"{Colors.FAIL}Error: run_agent.py not found at {script_path}{Colors.ENDC}")
        return
    
    # Change working directory to ai_agent_starter (where ai_agent module is)
    # This allows the script's sys.path.insert to work correctly
    original_dir = os.getcwd()
    os.chdir(base_dir)
    
    # Set PYTHONPATH to include the base directory
    env = os.environ.copy()
    env['PYTHONPATH'] = str(base_dir)
    
    # Run the agent script from correct working directory
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            env=env,
            cwd=str(base_dir),  # Ensure we run from base_dir
            check=True
        )
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}✅ Agent execution completed!{Colors.ENDC}")
        print(f"Check the report with: {Colors.OKCYAN}byebac /status{Colors.ENDC}\n")
    except subprocess.CalledProcessError as e:
        print(f"\n{Colors.FAIL}❌ Agent execution failed with error code {e.returncode}{Colors.ENDC}\n")
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠️  Agent execution interrupted by user{Colors.ENDC}\n")
    finally:
        # Restore original directory
        os.chdir(original_dir)

def open_report(date_str=None):
    """Open specific report or latest"""
    print_banner()
    
    base_dir = Path(__file__).parent
    runs_dir = base_dir / "ai_agent/runs"
    
    if date_str:
        # Try both old and new formats
        report_file = runs_dir / f"report-{date_str}.json"
        if not report_file.exists():
            report_file = runs_dir / f"BAC_Security_Test_Report-{date_str}.json"
        if not report_file.exists():
            print(f"{Colors.FAIL}Report not found: {date_str}{Colors.ENDC}\n")
            return
    else:
        # Find latest (support both old and new naming formats)
        report_files = (
            list(runs_dir.glob("report-*.json")) + 
            list(runs_dir.glob("BAC_Security_Test_Report-*.json"))
        )
        if not report_files:
            print(f"{Colors.WARNING}No reports found.{Colors.ENDC}\n")
            return
        report_file = max(report_files, key=lambda p: p.stat().st_mtime)
    
    print(f"{Colors.BOLD}Opening report:{Colors.ENDC} {Colors.OKCYAN}{report_file.name}{Colors.ENDC}\n")
    
    # Display report location
    print(f"JSON Report: {Colors.OKCYAN}{report_file}{Colors.ENDC}")
    
    # Check for HTML report
    html_file = report_file.with_suffix('.html')
    if html_file.exists():
        print(f"HTML Report: {Colors.OKCYAN}{html_file}{Colors.ENDC}")
    
    print()

def clean_artifacts():
    """Clean all test artifacts and old reports"""
    print_banner()
    print(f"\n{Colors.BOLD}{Colors.WARNING}🧹 Artifact Cleanup Utility{Colors.ENDC}\n")
    
    base_dir = Path(__file__).parent
    artifacts_dir = base_dir / "ai_agent/runs/artifacts"
    runs_dir = base_dir / "ai_agent/runs"
    
    if not artifacts_dir.exists():
        print(f"{Colors.WARNING}No artifacts directory found.{Colors.ENDC}\n")
        return
    
    # Count files to delete
    artifact_files = list(artifacts_dir.rglob("*.json"))
    # Support both old and new naming formats
    report_files = (
        list(runs_dir.glob("report-*.json")) + 
        list(runs_dir.glob("report-*.md")) +
        list(runs_dir.glob("BAC_Security_Test_Report-*.json")) +
        list(runs_dir.glob("BAC_Security_Test_Report-*.md"))
    )
    total_files = len(artifact_files) + len(report_files)
    
    if total_files == 0:
        print(f"{Colors.OKGREEN}✅ Already clean - no artifacts found.{Colors.ENDC}\n")
        return
    
    # Calculate total size
    total_size = sum(f.stat().st_size for f in artifact_files + report_files if f.exists())
    size_mb = total_size / (1024 * 1024)
    
    print(f"{Colors.BOLD}Files to delete:{Colors.ENDC}")
    print(f"  • Artifacts: {Colors.OKCYAN}{len(artifact_files)}{Colors.ENDC} files")
    print(f"  • Reports:   {Colors.OKCYAN}{len(report_files)}{Colors.ENDC} files")
    print(f"  • Total:     {Colors.OKCYAN}{total_files}{Colors.ENDC} files ({size_mb:.2f} MB)")
    print()
    
    # Confirmation prompt
    confirm = input(f"{Colors.WARNING}⚠️  Delete all artifacts and reports? (yes/no): {Colors.ENDC}").strip().lower()
    
    if confirm not in ['yes', 'y']:
        print(f"\n{Colors.OKBLUE}Cleanup cancelled.{Colors.ENDC}\n")
        return
    
    # Delete artifacts
    deleted_count = 0
    try:
        # Delete artifact files
        for f in artifact_files:
            try:
                f.unlink()
                deleted_count += 1
            except Exception as e:
                print(f"{Colors.FAIL}Error deleting {f.name}: {e}{Colors.ENDC}")
        
        # Delete report files
        for f in report_files:
            try:
                f.unlink()
                deleted_count += 1
            except Exception as e:
                print(f"{Colors.FAIL}Error deleting {f.name}: {e}{Colors.ENDC}")
        
        # Delete empty directories
        import shutil
        for role_dir in artifacts_dir.iterdir():
            if role_dir.is_dir() and role_dir.name != "YYYY_MM_DD":
                try:
                    shutil.rmtree(role_dir)
                except Exception:
                    pass
        
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}✅ Cleanup complete!{Colors.ENDC}")
        print(f"   Deleted {Colors.OKCYAN}{deleted_count}{Colors.ENDC} files ({size_mb:.2f} MB freed)")
        print()
    
    except Exception as e:
        print(f"\n{Colors.FAIL}❌ Cleanup failed: {e}{Colors.ENDC}\n")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='BYE BAC - Broken Access Control Detection CLI',
        add_help=False
    )
    
    parser.add_argument('command', nargs='?', default='/help',
                       help='Command to execute')
    parser.add_argument('args', nargs='*', help='Additional arguments')
    
    args = parser.parse_args()
    
    command = args.command.lower()
    
    # Route commands
    if command in ['/help', '-h', '--help', 'help']:
        show_help()
    elif command in ['/information', '/info', 'info']:
        show_information()
    elif command in ['/runagent', 'run', 'start']:
        run_agent()
    elif command in ['/specification', '/spec', 'spec']:
        show_specification()
    elif command in ['/check', 'check']:
        check_setup()
    elif command in ['/status', 'status']:
        show_status()
    elif command in ['/config', 'config']:
        show_config()
    elif command in ['/clean', 'clean', 'cleanup']:
        clean_artifacts()
    elif command in ['/report', 'report']:
        date_arg = args.args[0] if args.args else None
        open_report(date_arg)
    else:
        print(f"{Colors.FAIL}Unknown command: {command}{Colors.ENDC}")
        print(f"Type {Colors.OKCYAN}byebac /help{Colors.ENDC} for available commands.\n")

if __name__ == '__main__':
    main()
