import asyncio
import logging
import subprocess
from typing import Dict, Any

from superagentx.handler import BaseHandler

logger = logging.getLogger(__name__)

class TrafficAnalyzerHandler(BaseHandler):
    """
    Handler for capturing and analyzing network traffic using tshark.
    """

    async def capture_traffic(self, interface: str = "any", duration: int = 60, filter_expr: str = None, output_file: str = "/tmp/capture.pcap"):
        """
        Captures network traffic using tshark.
        """
        logger.info(f"Starting tshark capture on interface '{interface}' for {duration} seconds.")

        command = [
            "tshark",
            "-i", interface,
            "-a", f"duration:{duration}",
            "-w", output_file
        ]

        if filter_expr:
            command.extend(["-f", filter_expr])

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_message = stderr.decode().strip()
                logger.error(f"tshark capture failed: {error_message}")
                return {"status": "error", "message": error_message}

            logger.info(f"tshark capture successful. File saved to {output_file}")
            return {"status": "success", "pcap_file": output_file, "details": stdout.decode().strip()}

        except FileNotFoundError:
            logger.error("tshark command not found. Please ensure it is installed and in your PATH.")
            return {"status": "error", "message": "tshark command not found."}
        except Exception as e:
            logger.error(f"An error occurred during traffic capture: {e}")
            return {"status": "error", "message": str(e)}

    async def analyze_traffic(self, pcap_file: str, analysis_type: str = "protocols"):
        """
        Analyzes a pcap file using tshark.
        """
        logger.info(f"Analyzing pcap file '{pcap_file}' for '{analysis_type}'.")

        if analysis_type == "protocols":
            command = ["tshark", "-r", pcap_file, "-q", "-z", "proto,col"]
        elif analysis_type == "hosts":
            command = ["tshark", "-r", pcap_file, "-q", "-z", "conv,ip"]
        elif analysis_type == "flows":
            command = ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"]
        else:
            return {"status": "error", "message": f"Unknown analysis type: {analysis_type}"}

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_message = stderr.decode().strip()
                logger.error(f"tshark analysis failed: {error_message}")
                return {"status": "error", "message": error_message}

            analysis_result = stdout.decode().strip()
            logger.info("tshark analysis successful.")
            return {"status": "success", "analysis_results": analysis_result}

        except FileNotFoundError:
            logger.error("tshark command not found. Please ensure it is installed and in your PATH.")
            return {"status": "error", "message": "tshark command not found."}
        except Exception as e:
            logger.error(f"An error occurred during traffic analysis: {e}")
            return {"status": "error", "message": str(e)}
