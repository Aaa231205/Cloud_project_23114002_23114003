import logging
import os

LOGS_DIR = os.path.join("/app", "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

def setup_logger(name, log_file, level=logging.INFO):
    """Function to setup as many loggers as you want"""
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    handler = logging.FileHandler(os.path.join(LOGS_DIR, log_file))
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        logger.addHandler(handler)
        
    return logger

auth_logger = setup_logger("Auth", "auth.log")
threat_logger = setup_logger("Threat", "threats.log")
mitigation_logger = setup_logger("Mitigation", "mitigation.log")

def log_auth_success(username, ip_address):
    auth_logger.info(f"Successful login - User: {username} - IP: {ip_address}")

def log_auth_failure(username, ip_address, reason="Invalid credentials"):
    auth_logger.warning(f"Failed login attempt - User: {username} - IP: {ip_address} - Reason: {reason}")
    threat_logger.warning(f"Potential Brute Force Indicator - User: {username} - IP: {ip_address}")

def log_ip_blocked(ip_address, duration_mins):
    mitigation_logger.error(f"IP BLOCKED - Automtated Mitigation Triggered - IP: {ip_address} blocked for {duration_mins} minutes.")

def log_account_locked(username, duration_mins):
    mitigation_logger.error(f"ACCOUNT LOCKED - Automtated Mitigation Triggered - User: {username} locked for {duration_mins} minutes.")
    
def log_security_event(event_type, details, ip_address="Unknown"):
    threat_logger.warning(f"Security Event: {event_type} - Details: {details} - IP: {ip_address}")
