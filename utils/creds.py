from enum import Enum
import os
import keyring

class Creds(Enum):
    """
    Secure storage for database credentials
    Retrieves credentials from environment variables or keyring
    """
    db_username = os.getenv('DB_USERNAME') or keyring.get_password('system', 'db_username')
    db_password = os.getenv('DB_PASSWORD') or keyring.get_password('system', 'db_password')
    snowflake_user = os.getenv('SNOWFLAKE_USER') or keyring.get_password('system', 'snowflake_user')
    snowflake_password = os.getenv('SNOWFLAKE_PASSWORD') or keyring.get_password('system', 'snowflake_password')