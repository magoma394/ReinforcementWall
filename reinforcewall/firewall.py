"""
Firewall module for ReinforceWall.

This module handles defensive actions including blocking IPs, logging,
and alerting. Supports both simulation mode (safe for demos) and
real iptables integration (requires sudo).
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from reinforcewall.config import FIREWALL_CONFIG
from reinforcewall.logger import logger


class Firewall:
    """Firewall for executing defensive actions."""
    
    def __init__(self, simulation_mode: Optional[bool] = None):
        """
        Initialize firewall.
        
        Args:
            simulation_mode: If True, simulate actions without real iptables.
                           If None, uses FIREWALL_CONFIG.SIMULATION_MODE
        """
        self.simulation_mode = (
            simulation_mode
            if simulation_mode is not None
            else FIREWALL_CONFIG.SIMULATION_MODE
        )
        
        # Initialize logging directories
        self.log_dir = Path(FIREWALL_CONFIG.LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.alert_log = self.log_dir / "alerts.log"
        self.traffic_log = self.log_dir / "traffic.log"
        
        # Track blocked IPs (in-memory for simulation)
        self.blocked_ips: set = set()
        
        # Check sudo access if not in simulation mode
        if not self.simulation_mode:
            self._check_sudo_access()
    
    def _check_sudo_access(self):
        """Check if sudo access is available for iptables."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.firewall_logger.warning(
                    "Sudo access not available. Switching to simulation mode."
                )
                self.simulation_mode = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.firewall_logger.warning(
                "Sudo check failed. Switching to simulation mode."
            )
            self.simulation_mode = True
    
    def block_ip(self, ip_address: str, reason: str = "Attack detected") -> bool:
        """
        Block an IP address using iptables.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
        
        Returns:
            True if successful, False otherwise
        """
        if self.simulation_mode:
            return self._simulate_block(ip_address, reason)
        
        return self._real_block(ip_address, reason)
    
    def _simulate_block(self, ip_address: str, reason: str) -> bool:
        """Simulate blocking an IP (no actual iptables command)."""
        if ip_address in self.blocked_ips:
            logger.firewall_logger.info(
                f"IP {ip_address} already blocked (simulation)"
            )
            return True
        
        self.blocked_ips.add(ip_address)
        
        # Log the action
        log_entry = (
            f"[{datetime.now().isoformat()}] "
            f"BLOCKED (SIMULATION) - IP: {ip_address}, Reason: {reason}\n"
        )
        
        with open(self.alert_log, "a") as f:
            f.write(log_entry)
        
        logger.firewall_logger.info(
            f"Simulated blocking IP {ip_address}: {reason}"
        )
        logger.log_firewall_action("block", ip_address, True, reason)
        
        return True
    
    def _real_block(self, ip_address: str, reason: str) -> bool:
        """Actually block an IP using iptables (requires sudo)."""
        try:
            # Check if rule already exists
            check_cmd = [
                "sudo",
                "iptables",
                "-C",
                FIREWALL_CONFIG.IPTABLES_CHAIN,
                "-s",
                ip_address,
                "-j",
                "DROP"
            ]
            
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Rule already exists
                logger.firewall_logger.info(
                    f"IP {ip_address} already blocked in iptables"
                )
                return True
            
            # Add blocking rule
            block_cmd = [
                "sudo",
                "iptables",
                "-A",
                FIREWALL_CONFIG.IPTABLES_CHAIN,
                "-s",
                ip_address,
                "-j",
                "DROP"
            ]
            
            result = subprocess.run(
                block_cmd,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                log_entry = (
                    f"[{datetime.now().isoformat()}] "
                    f"BLOCKED - IP: {ip_address}, Reason: {reason}\n"
                )
                
                with open(self.alert_log, "a") as f:
                    f.write(log_entry)
                
                logger.firewall_logger.info(
                    f"Blocked IP {ip_address} in iptables: {reason}"
                )
                logger.log_firewall_action("block", ip_address, True, reason)
                return True
            else:
                error_msg = result.stderr or "Unknown error"
                logger.firewall_logger.error(
                    f"Failed to block IP {ip_address}: {error_msg}"
                )
                logger.log_firewall_action("block", ip_address, False, error_msg)
                return False
                
        except subprocess.TimeoutExpired:
            logger.firewall_logger.error(
                f"Timeout while blocking IP {ip_address}"
            )
            return False
        except Exception as e:
            logger.firewall_logger.error(
                f"Exception while blocking IP {ip_address}: {str(e)}"
            )
            return False
    
    def alert(self, ip_address: str, attack_type: str, details: Dict[str, Any]) -> bool:
        """
        Log an alert for suspicious activity.
        
        Args:
            ip_address: IP address that triggered the alert
            attack_type: Type of attack detected
            details: Additional details about the alert
        
        Returns:
            True if successful
        """
        timestamp = datetime.now().isoformat()
        log_entry = (
            f"[{timestamp}] ALERT - IP: {ip_address}, "
            f"Attack Type: {attack_type}, Details: {details}\n"
        )
        
        try:
            with open(self.alert_log, "a") as f:
                f.write(log_entry)
            
            logger.log_attack(attack_type, ip_address, details)
            logger.log_firewall_action("alert", ip_address, True, attack_type)
            return True
        except Exception as e:
            logger.firewall_logger.error(
                f"Failed to write alert log: {str(e)}"
            )
            return False
    
    def log(self, ip_address: str, request_data: Dict[str, Any]) -> bool:
        """
        Log a request for audit purposes.
        
        Args:
            ip_address: IP address of the request
            request_data: Request metadata (endpoint, method, etc.)
        
        Returns:
            True if successful
        """
        timestamp = datetime.now().isoformat()
        log_entry = (
            f"[{timestamp}] LOG - IP: {ip_address}, "
            f"Request: {request_data}\n"
        )
        
        try:
            with open(self.traffic_log, "a") as f:
                f.write(log_entry)
            
            logger.firewall_logger.debug(
                f"Logged request from {ip_address}"
            )
            logger.log_firewall_action("log", ip_address, True, str(request_data))
            return True
        except Exception as e:
            logger.firewall_logger.error(
                f"Failed to write traffic log: {str(e)}"
            )
            return False
    
    def ignore(self) -> bool:
        """
        No action taken (explicit ignore).
        
        Returns:
            Always True (no action to fail)
        """
        # This is a no-op, but we log it for completeness
        logger.firewall_logger.debug("Action: IGNORE (no action taken)")
        return True
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address (remove iptables rule).
        
        Args:
            ip_address: IP address to unblock
        
        Returns:
            True if successful, False otherwise
        """
        if self.simulation_mode:
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                logger.firewall_logger.info(
                    f"Unblocked IP {ip_address} (simulation)"
                )
                return True
            return False
        
        # Real iptables unblock
        try:
            unblock_cmd = [
                "sudo",
                "iptables",
                "-D",
                FIREWALL_CONFIG.IPTABLES_CHAIN,
                "-s",
                ip_address,
                "-j",
                "DROP"
            ]
            
            result = subprocess.run(
                unblock_cmd,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                logger.firewall_logger.info(
                    f"Unblocked IP {ip_address} in iptables"
                )
                return True
            else:
                logger.firewall_logger.warning(
                    f"Failed to unblock IP {ip_address}: {result.stderr}"
                )
                return False
        except Exception as e:
            logger.firewall_logger.error(
                f"Exception while unblocking IP {ip_address}: {str(e)}"
            )
            return False
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP is currently blocked.
        
        Args:
            ip_address: IP address to check
        
        Returns:
            True if blocked, False otherwise
        """
        if self.simulation_mode:
            return ip_address in self.blocked_ips
        
        # Check iptables
        try:
            check_cmd = [
                "sudo",
                "iptables",
                "-C",
                FIREWALL_CONFIG.IPTABLES_CHAIN,
                "-s",
                ip_address,
                "-j",
                "DROP"
            ]
            
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                timeout=5
            )
            
            return result.returncode == 0
        except Exception:
            return False
    
    def reset(self):
        """Reset firewall state (clear blocked IPs in simulation mode)."""
        if self.simulation_mode:
            self.blocked_ips.clear()
            logger.firewall_logger.info("Reset firewall (simulation mode)")

