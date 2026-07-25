import logging
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
import sys

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra fields if they exist
        if hasattr(record, "extra_fields"):
            log_record.update(record.extra_fields)
            
        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
            
        return json.dumps(log_record)

def setup_logger(name: str, log_file: str = "logs/security_monitor.log") -> logging.Logger:
    import os
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers if setup_logger is called multiple times
    if logger.handlers:
        return logger
        
    # Rotate at 10MB, keep 5 backups
    file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
    file_handler.setFormatter(JSONFormatter())
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter())
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger
