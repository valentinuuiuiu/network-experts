"""
MQTT Handler for Network Experts Team
Handles MQTT broker operations, topic management, and IoT device communication
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
import ssl

try:
    import paho.mqtt.client as mqtt
    import aiomqtt
except ImportError:
    print("Installing MQTT dependencies...")
    import subprocess
    subprocess.run(["pip", "install", "paho-mqtt", "aiomqtt"])
    import paho.mqtt.client as mqtt
    import aiomqtt

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class MQTTHandler(BaseHandler):
    """
    MQTT Handler for managing IoT network communications
    The MQTT Brother - Expert in IoT device communication and message brokering
    """

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = False,
        client_id: Optional[str] = None
    ):
        super().__init__()
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.client_id = client_id or "network_expert_mqtt"
        self.client = None
        self.subscribed_topics = {}
        self.message_buffer = []

    async def _connect(self):
        """Establish connection to MQTT broker"""
        try:
            self.client = aiomqtt.Client(
                hostname=self.broker_host,
                port=self.broker_port,
                username=self.username,
                password=self.password,
                identifier=self.client_id,
                tls_context=ssl.create_default_context() if self.use_tls else None
            )
            await self.client.__aenter__()
            logger.info(f"Connected to MQTT broker at {self.broker_host}:{self.broker_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            return False

    @tool
    async def discover_mqtt_brokers(
        self,
        *,
        network_range: str = "192.168.1.0/24",
        ports: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Discover MQTT brokers in the network
        
        Args:
            network_range: Network range to scan (CIDR notation)
            ports: List of ports to check for MQTT brokers
            
        Returns:
            Dictionary with discovered MQTT brokers
        """
        if ports is None:
            ports = [1883, 8883, 1884]  # Common MQTT ports
            
        discovered_brokers = []
        
        try:
            import ipaddress
            import socket
            
            network = ipaddress.IPv4Network(network_range, strict=False)
            
            for ip in network.hosts():
                ip_str = str(ip)
                for port in ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip_str, port))
                        sock.close()
                        
                        if result == 0:
                            # Try to connect with MQTT client to verify
                            try:
                                test_client = mqtt.Client()
                                test_client.connect(ip_str, port, 5)
                                test_client.disconnect()
                                
                                discovered_brokers.append({
                                    "host": ip_str,
                                    "port": port,
                                    "status": "active",
                                    "protocol": "MQTT"
                                })
                                logger.info(f"Found MQTT broker at {ip_str}:{port}")
                            except:
                                pass
                    except Exception as e:
                        continue
                        
        except Exception as e:
            logger.error(f"Error discovering MQTT brokers: {e}")
            
        return {
            "discovered_brokers": discovered_brokers,
            "total_found": len(discovered_brokers),
            "scan_range": network_range,
            "ports_scanned": ports
        }

    @tool
    async def publish_message(
        self,
        *,
        topic: str,
        message: str,
        qos: int = 0,
        retain: bool = False
    ) -> Dict[str, Any]:
        """
        Publish a message to an MQTT topic
        
        Args:
            topic: MQTT topic to publish to
            message: Message payload
            qos: Quality of Service level (0, 1, or 2)
            retain: Whether to retain the message
            
        Returns:
            Publication result
        """
        try:
            if not self.client:
                await self._connect()
                
            await self.client.publish(topic, message, qos=qos, retain=retain)
            
            result = {
                "status": "success",
                "topic": topic,
                "message_length": len(message),
                "qos": qos,
                "retain": retain,
                "timestamp": asyncio.get_event_loop().time()
            }
            
            logger.info(f"Published message to topic '{topic}': {message[:50]}...")
            return result
            
        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            return {
                "status": "error",
                "error": str(e),
                "topic": topic
            }

    @tool
    async def subscribe_to_topic(
        self,
        *,
        topic: str,
        qos: int = 0,
        timeout: int = 10
    ) -> Dict[str, Any]:
        """
        Subscribe to an MQTT topic and collect messages
        
        Args:
            topic: MQTT topic to subscribe to
            qos: Quality of Service level
            timeout: How long to listen for messages (seconds)
            
        Returns:
            Collected messages from the topic
        """
        messages = []
        
        try:
            if not self.client:
                await self._connect()
                
            await self.client.subscribe(topic, qos=qos)
            logger.info(f"Subscribed to topic: {topic}")
            
            # Listen for messages
            start_time = asyncio.get_event_loop().time()
            
            async with self.client.messages() as messages_queue:
                async for message in messages_queue:
                    if asyncio.get_event_loop().time() - start_time > timeout:
                        break
                        
                    msg_data = {
                        "topic": message.topic.value,
                        "payload": message.payload.decode(),
                        "qos": message.qos,
                        "retain": message.retain,
                        "timestamp": asyncio.get_event_loop().time()
                    }
                    messages.append(msg_data)
                    
                    if len(messages) >= 100:  # Limit message collection
                        break
                        
        except Exception as e:
            logger.error(f"Failed to subscribe to topic: {e}")
            return {
                "status": "error",
                "error": str(e),
                "topic": topic
            }
            
        return {
            "status": "success",
            "topic": topic,
            "messages": messages,
            "message_count": len(messages),
            "listen_duration": timeout
        }

    @tool
    async def analyze_mqtt_traffic(
        self,
        *,
        topics: Optional[List[str]] = None,
        duration: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze MQTT traffic patterns
        
        Args:
            topics: List of topics to monitor (or all if None)
            duration: Monitoring duration in seconds
            
        Returns:
            Traffic analysis results
        """
        if topics is None:
            topics = ["#"]  # Subscribe to all topics
            
        traffic_stats = {
            "total_messages": 0,
            "topics_activity": {},
            "message_sizes": [],
            "qos_distribution": {0: 0, 1: 0, 2: 0},
            "retained_messages": 0
        }
        
        try:
            if not self.client:
                await self._connect()
                
            for topic in topics:
                await self.client.subscribe(topic)
                
            start_time = asyncio.get_event_loop().time()
            
            async with self.client.messages() as messages_queue:
                async for message in messages_queue:
                    if asyncio.get_event_loop().time() - start_time > duration:
                        break
                        
                    # Update statistics
                    traffic_stats["total_messages"] += 1
                    
                    topic = message.topic.value
                    if topic not in traffic_stats["topics_activity"]:
                        traffic_stats["topics_activity"][topic] = 0
                    traffic_stats["topics_activity"][topic] += 1
                    
                    traffic_stats["message_sizes"].append(len(message.payload))
                    traffic_stats["qos_distribution"][message.qos] += 1
                    
                    if message.retain:
                        traffic_stats["retained_messages"] += 1
                        
        except Exception as e:
            logger.error(f"Error analyzing MQTT traffic: {e}")
            return {"status": "error", "error": str(e)}
            
        # Calculate additional metrics
        if traffic_stats["message_sizes"]:
            traffic_stats["avg_message_size"] = sum(traffic_stats["message_sizes"]) / len(traffic_stats["message_sizes"])
            traffic_stats["max_message_size"] = max(traffic_stats["message_sizes"])
            traffic_stats["min_message_size"] = min(traffic_stats["message_sizes"])
        
        traffic_stats["messages_per_second"] = traffic_stats["total_messages"] / duration
        traffic_stats["monitoring_duration"] = duration
        
        return {
            "status": "success",
            "analysis": traffic_stats,
            "most_active_topics": sorted(
                traffic_stats["topics_activity"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }

    @tool
    async def get_broker_info(self, *, broker_host: Optional[str] = None) -> Dict[str, Any]:
        """
        Get information about the MQTT broker
        
        Args:
            broker_host: Broker host to check (uses default if None)
            
        Returns:
            Broker information and capabilities
        """
        host = broker_host or self.broker_host
        
        try:
            # Try to connect and get broker info
            test_client = mqtt.Client()
            
            broker_info = {
                "host": host,
                "port": self.broker_port,
                "connection_status": "unknown",
                "broker_version": "unknown",
                "max_qos": "unknown",
                "retain_available": "unknown",
                "wildcard_subscription_available": "unknown"
            }
            
            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    broker_info["connection_status"] = "connected"
                else:
                    broker_info["connection_status"] = f"failed (code: {rc})"
                    
            test_client.on_connect = on_connect
            test_client.connect(host, self.broker_port, 5)
            test_client.loop_start()
            
            await asyncio.sleep(2)  # Wait for connection
            
            test_client.loop_stop()
            test_client.disconnect()
            
            return {
                "status": "success",
                "broker_info": broker_info
            }
            
        except Exception as e:
            logger.error(f"Error getting broker info: {e}")
            return {
                "status": "error",
                "error": str(e),
                "host": host
            }

    async def cleanup(self):
        """Clean up MQTT connections"""
        try:
            if self.client:
                await self.client.__aexit__(None, None, None)
                logger.info("MQTT client disconnected")
        except Exception as e:
            logger.error(f"Error during MQTT cleanup: {e}")
