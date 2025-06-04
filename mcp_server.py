"""
MCP Server for Network Experts Team
Integrates MQTT and Node-RED capabilities as MCP tools
"""

import asyncio
import json
import logging
import gradio as gr
from typing import Dict, List, Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import sse_server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource

from network_experts.handlers.mqtt_handler import MQTTHandler
from network_experts.handlers.node_red_handler import NodeRedHandler
from network_experts.handlers.network_scan import NetworkScanHandler
from network_experts.handlers.security_audit import SecurityAuditHandler
from network_experts.handlers.traffic_analyzer import TrafficAnalyzerHandler

logger = logging.getLogger(__name__)

# Initialize server
server = Server("network-experts-mcp")

# Initialize handlers
mqtt_handler = MQTTHandler()
node_red_handler = NodeRedHandler()
network_scanner = NetworkScanHandler()
security_auditor = SecurityAuditHandler()
traffic_analyzer = TrafficAnalyzerHandler()


@server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available tools from Network Experts team"""
    
    tools = [
        # MQTT Tools
        Tool(
            name="discover_mqtt_brokers",
            description="Discover MQTT brokers in the network",
            inputSchema={
                "type": "object",
                "properties": {
                    "network_range": {
                        "type": "string",
                        "description": "Network range to scan (CIDR notation)",
                        "default": "192.168.1.0/24"
                    },
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of ports to check for MQTT brokers",
                        "default": [1883, 8883, 1884]
                    }
                }
            }
        ),
        Tool(
            name="publish_mqtt_message",
            description="Publish a message to an MQTT topic",
            inputSchema={
                "type": "object",
                "required": ["topic", "message"],
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "MQTT topic to publish to"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message payload"
                    },
                    "qos": {
                        "type": "integer",
                        "description": "Quality of Service level (0, 1, or 2)",
                        "default": 0
                    },
                    "retain": {
                        "type": "boolean",
                        "description": "Whether to retain the message",
                        "default": False
                    }
                }
            }
        ),
        Tool(
            name="subscribe_mqtt_topic",
            description="Subscribe to an MQTT topic and collect messages",
            inputSchema={
                "type": "object",
                "required": ["topic"],
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "MQTT topic to subscribe to"
                    },
                    "qos": {
                        "type": "integer",
                        "description": "Quality of Service level",
                        "default": 0
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "How long to listen for messages (seconds)",
                        "default": 10
                    }
                }
            }
        ),
        Tool(
            name="analyze_mqtt_traffic",
            description="Analyze MQTT traffic patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "topics": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of topics to monitor (or all if empty)"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Monitoring duration in seconds",
                        "default": 30
                    }
                }
            }
        ),
        
        # Node-RED Tools
        Tool(
            name="check_node_red_status",
            description="Check Node-RED server status and health",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_node_red_flows",
            description="Get all flows from Node-RED",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="create_network_monitoring_flow",
            description="Create a network monitoring flow in Node-RED",
            inputSchema={
                "type": "object",
                "required": ["target_hosts"],
                "properties": {
                    "target_hosts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of hosts to monitor"
                    },
                    "check_interval": {
                        "type": "integer",
                        "description": "Check interval in seconds",
                        "default": 60
                    },
                    "mqtt_topic": {
                        "type": "string",
                        "description": "MQTT topic to publish results",
                        "default": "network/status"
                    }
                }
            }
        ),
        Tool(
            name="backup_node_red_flows",
            description="Backup Node-RED flows to file",
            inputSchema={
                "type": "object",
                "properties": {
                    "backup_path": {
                        "type": "string",
                        "description": "Path to save backup file"
                    }
                }
            }
        ),
        
        # Network Scanning Tools
        Tool(
            name="scan_network",
            description="Scan network for active hosts and services",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or network range"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["ping", "tcp", "udp", "comprehensive"],
                        "description": "Type of scan to perform",
                        "default": "ping"
                    },
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Specific ports to scan"
                    }
                }
            }
        ),
        Tool(
            name="port_scan",
            description="Perform detailed port scanning on target hosts",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port_range": {
                        "type": "string",
                        "description": "Port range to scan (e.g., '1-1000')",
                        "default": "1-1000"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["tcp", "udp", "syn"],
                        "description": "Type of port scan",
                        "default": "tcp"
                    }
                }
            }
        ),
        
        # Security Audit Tools
        Tool(
            name="vulnerability_scan",
            description="Perform vulnerability scanning on network targets",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or network range"
                    },
                    "scan_depth": {
                        "type": "string",
                        "enum": ["basic", "intermediate", "deep"],
                        "description": "Depth of vulnerability scan",
                        "default": "basic"
                    }
                }
            }
        ),
        Tool(
            name="security_assessment",
            description="Comprehensive security assessment of network infrastructure",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target network or host to assess"
                    },
                    "assessment_type": {
                        "type": "string",
                        "enum": ["network", "web", "infrastructure"],
                        "description": "Type of security assessment",
                        "default": "network"
                    }
                }
            }
        ),
        
        # Traffic Analysis Tools
        Tool(
            name="capture_network_traffic",
            description="Capture and analyze network traffic",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Network interface to capture from",
                        "default": "any"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Capture duration in seconds",
                        "default": 60
                    },
                    "filter": {
                        "type": "string",
                        "description": "BPF filter expression"
                    }
                }
            }
        ),
        Tool(
            name="analyze_traffic_patterns",
            description="Analyze network traffic patterns and statistics",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Path to PCAP file to analyze"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["protocols", "hosts", "flows", "anomalies"],
                        "description": "Type of analysis to perform",
                        "default": "protocols"
                    }
                }
            }
        )
    ]
    
    return tools


@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute tool calls from Network Experts team"""
    
    try:
        result = None
        
        # MQTT Handler Tools
        if name == "discover_mqtt_brokers":
            result = await mqtt_handler.discover_mqtt_brokers(**arguments)
        elif name == "publish_mqtt_message":
            result = await mqtt_handler.publish_message(
                topic=arguments["topic"],
                message=arguments["message"],
                qos=arguments.get("qos", 0),
                retain=arguments.get("retain", False)
            )
        elif name == "subscribe_mqtt_topic":
            result = await mqtt_handler.subscribe_to_topic(
                topic=arguments["topic"],
                qos=arguments.get("qos", 0),
                timeout=arguments.get("timeout", 10)
            )
        elif name == "analyze_mqtt_traffic":
            result = await mqtt_handler.analyze_mqtt_traffic(
                topics=arguments.get("topics"),
                duration=arguments.get("duration", 30)
            )
            
        # Node-RED Handler Tools
        elif name == "check_node_red_status":
            result = await node_red_handler.check_node_red_status()
        elif name == "get_node_red_flows":
            result = await node_red_handler.get_flows()
        elif name == "create_network_monitoring_flow":
            result = await node_red_handler.create_network_monitoring_flow(
                target_hosts=arguments["target_hosts"],
                check_interval=arguments.get("check_interval", 60),
                mqtt_topic=arguments.get("mqtt_topic", "network/status")
            )
        elif name == "backup_node_red_flows":
            result = await node_red_handler.backup_flows(
                backup_path=arguments.get("backup_path")
            )
            
        # Network Scanning Tools
        elif name == "scan_network":
            result = await network_scanner.scan_network(
                target=arguments["target"],
                scan_type=arguments.get("scan_type", "ping"),
                ports=arguments.get("ports")
            )
        elif name == "port_scan":
            result = await network_scanner.port_scan(
                target=arguments["target"],
                port_range=arguments.get("port_range", "1-1000"),
                scan_type=arguments.get("scan_type", "tcp")
            )
            
        # Security Audit Tools
        elif name == "vulnerability_scan":
            result = await security_auditor.vulnerability_scan(
                target=arguments["target"],
                scan_depth=arguments.get("scan_depth", "basic")
            )
        elif name == "security_assessment":
            result = await security_auditor.security_assessment(
                target=arguments["target"],
                assessment_type=arguments.get("assessment_type", "network")
            )
            
        # Traffic Analysis Tools
        elif name == "capture_network_traffic":
            result = await traffic_analyzer.capture_traffic(
                interface=arguments.get("interface", "any"),
                duration=arguments.get("duration", 60),
                filter_expr=arguments.get("filter")
            )
        elif name == "analyze_traffic_patterns":
            result = await traffic_analyzer.analyze_traffic(
                pcap_file=arguments.get("pcap_file"),
                analysis_type=arguments.get("analysis_type", "protocols")
            )
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
            
        # Format result as JSON
        result_text = json.dumps(result, indent=2, default=str)
        return [TextContent(type="text", text=result_text)]
        
    except Exception as e:
        error_msg = f"Error executing {name}: {str(e)}"
        logger.error(error_msg)
        return [TextContent(type="text", text=error_msg)]


def create_gradio_interface():
    """Create Gradio interface for MCP control"""
    with gr.Blocks(title="Network Experts MCP Dashboard") as interface:
        gr.Markdown("# 🛠️ Network Experts MCP Control Panel")
        
        with gr.Tab("MQTT Tools"):
            with gr.Row():
                mqtt_tool = gr.Dropdown(
                    ["discover_mqtt_brokers", "publish_mqtt_message", 
                     "subscribe_mqtt_topic", "analyze_mqtt_traffic"],
                    label="Select MQTT Tool"
                )
            with gr.Row():
                mqtt_input = gr.JSON(label="Parameters")
                mqtt_output = gr.JSON(label="Results")
            mqtt_btn = gr.Button("Execute")
            mqtt_btn.click(
                lambda tool, params: asyncio.run(call_tool(tool, params)),
                inputs=[mqtt_tool, mqtt_input],
                outputs=mqtt_output
            )

        with gr.Tab("Network Tools"):
            # Similar structure for network tools...
        
        return interface

async def main():
    """Run the Network Experts MCP server with Gradio"""
    import sys
    
    # Create and launch Gradio interface
    gradio_app = create_gradio_interface()
    gradio_task = asyncio.create_task(
        gradio_app.launch(server_name="0.0.0.0", server_port=7861, share=False)
    )
    
    if len(sys.argv) > 1 and sys.argv[1] == "--sse":
        async with sse_server(server, host="0.0.0.0", port=8080) as (server_instance, url):
            print(f"Network Experts MCP running:\n- SSE: {url}\n- Gradio: http://0.0.0.0:7861")
            await server_instance.serve_forever()
    else:
        # Run as stdio server with Gradio
        async with stdio_server() as streams:
            print(f"Network Experts MCP running with Gradio at http://0.0.0.0:7861")
            try:
                await asyncio.gather(
                    server.run(*streams, server.create_initialization_options()),
                    gradio_task
                )
            except asyncio.CancelledError:
                gradio_app.close()
                raise


if __name__ == "__main__":
    asyncio.run(main())
