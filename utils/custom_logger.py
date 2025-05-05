import logging
from datetime import datetime
import os
import inspect
import sys

def customLogger(script_name=None):
    """
    Create and configure a custom logger that tracks which script generated the log

    Parameters:
    script_name (str, optional): Name of the script. If None, will attempt to detect automatically.
    
    Returns:
    logging.Logger: Configured logger instance
    """
    # Identify the script name if not provided
    if script_name is None:
        # Get the filename of the module that called this function
        frame = inspect.currentframe().f_back
        module = inspect.getmodule(frame)
        if module:
            script_name = os.path.basename(module.__file__)
        else:
            # Fallback if module detection fails
            script_name = os.path.basename(sys.argv[0])

    # Create logs directory structure
    cur_path = os.path.abspath(os.path.dirname(__file__))
    log_dir = os.path.join(cur_path, r"../logs/")

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)  # Use makedirs to create all needed directories

    date_dir = os.path.join(log_dir, str(datetime.strftime(datetime.now(), '%d%m%Y')))

    if not os.path.exists(date_dir):
        os.makedirs(date_dir)
   
    # Get or create logger with the script name
    logger = logging.getLogger(script_name)
    
    if not logger.handlers:
        # Configure logger if it doesn't already have handlers
        # Include script name in the log format
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        formatter = logging.Formatter(log_format)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler with timestamp in filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        log_filename = os.path.join(date_dir, f"log_{timestamp}.log")
        file_handler = logging.FileHandler(log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Set log level
        logger.setLevel(logging.INFO)
        
        # Log that this logger was initialized
        logger.debug(f"Logger initialized for {script_name}")
    
    return logger