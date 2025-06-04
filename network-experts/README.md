# Network Experts Team 🌐

A specialized team of AI agents built with SuperAgentX for comprehensive network analysis, monitoring, and management.

## Meet the Network Experts Brothers

### 🔍 **Scanner Brother** - Network Discovery Specialist
- **Role**: Network reconnaissance and device discovery
- **Capabilities**: 
  - Port scanning and service detection
  - Network topology mapping
  - Device fingerprinting
  - Vulnerability assessment

### 🛡️ **Security Brother** - Network Security Analyst
- **Role**: Security monitoring and threat detection
- **Capabilities**:
  - Security vulnerability scanning
  - Intrusion detection
  - Firewall rule analysis
  - Security compliance checking

### 📊 **Monitor Brother** - Performance Monitoring Expert
- **Role**: Network performance and health monitoring
- **Capabilities**:
  - Bandwidth monitoring
  - Latency analysis
  - Traffic pattern analysis
  - Performance bottleneck identification

### 🔧 **Config Brother** - Network Configuration Manager
- **Role**: Network device configuration and management
- **Capabilities**:
  - Device configuration backup/restore
  - Configuration compliance checking
  - Automated configuration deployment
  - Change management

### 🚨 **Troubleshoot Brother** - Network Problem Solver
- **Role**: Network issue diagnosis and resolution
- **Capabilities**:
  - Network connectivity testing
  - DNS resolution analysis
  - Route tracing and analysis
  - Performance troubleshooting

## Installation

### Prerequisites
- Python 3.11+
- Poetry for dependency management

### Setup
```bash
# Clone and navigate to project
cd network_experts

# Install dependencies with Poetry
poetry install

# Activate virtual environment
poetry shell

# Set up environment variables
export OPENAI_API_KEY="your-openai-api-key"
```

## Usage

### Quick Start
```python
import asyncio
from network_experts.team import NetworkExpertsTeam

async def main():
    # Initialize the network experts team
    team = NetworkExpertsTeam()
    
    # Run network analysis
    result = await team.analyze_network("192.168.1.0/24")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
```

### Individual Expert Usage
```python
from network_experts.agents import ScannerBrother, SecurityBrother

# Use Scanner Brother for network discovery
scanner = ScannerBrother()
devices = await scanner.scan_network("192.168.1.0/24")

# Use Security Brother for vulnerability assessment
security = SecurityBrother()
vulnerabilities = await security.assess_security("192.168.1.1")
```

## Features

- 🤖 **AI-Powered Analysis**: Leverages LLMs for intelligent network analysis
- 🔄 **Multi-Agent Collaboration**: Agents work together for comprehensive analysis
- 📈 **Real-time Monitoring**: Continuous network health monitoring
- 🛡️ **Security Focus**: Built-in security assessment capabilities
- 📊 **Rich Reporting**: Detailed analysis reports with recommendations
- 🔧 **Automation**: Automated network management tasks

## Architecture

```
Network Experts Team
├── Scanner Brother (Discovery)
├── Security Brother (Security)
├── Monitor Brother (Performance)
├── Config Brother (Management)
└── Troubleshoot Brother (Diagnostics)
```

Each brother specializes in specific network domains while collaborating through SuperAgentX's multi-agent framework.

## Gradio Interface 🖥️

New real-time communication interface available via:
```bash
python gradio_interface.py
```

### Features:
- Real-time chat with any Network Expert
- Visual conversation history
- System status monitoring
- Ready for Hugging Face Spaces deployment

### Spaces Deployment:
1. Create new Space on Hugging Face
2. Set environment variables:
   - `A2A_SERVER_URL`
   - `HUGGING_FACE_TOKEN` 
   - `OPENAI_API_KEY`

## License

MIT License - See LICENSE file for details.
