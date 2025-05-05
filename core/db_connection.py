import os
import sys
import pyodbc
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
import urllib
from contextlib import contextmanager
from typing import Tuple, Optional, Any
from utils.creds import Creds
from snowflake import connector
from utils import custom_logger

logger = custom_logger.customLogger()

class DatabaseConnection:
    """Class for handling various database connections"""
    
    @staticmethod
    def create_db_connection(server_name: str, database_name: str, autocommit: bool = True) -> pyodbc.Connection:
        """
        Create a connection to SQL Server using Windows authentication
        
        Args:
            server_name (str): SQL Server instance name
            database_name (str): Database name
            autocommit (bool, optional): Set autocommit mode. Defaults to True.
            
        Returns:
            pyodbc.Connection: Database connection object
            
        Raises:
            ConnectionError: If connection cannot be established
        """
        try:
            connection_string = (
                r"Driver={ODBC Driver 17 for SQL Server};"
                f"Server={server_name};"
                f"Database={database_name};"
                "Trusted_Connection=yes;"
            )
            
            # Disable connection pooling before establishing connection
            pyodbc.pooling = False
            
            db_conn = pyodbc.connect(connection_string, autocommit=autocommit)
            logger.info("DB Connection established successfully")
            return db_conn
            
        except pyodbc.Error as e:
            error_msg = f"Failed to establish DB connection: {e}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
    
    @staticmethod
    def create_db_connection_snowflake(
        account: str, 
        database: str, 
        warehouse: str, 
        role: str
    ) -> connector.SnowflakeConnection:
        """
        Create a connection to Snowflake database
        
        Args:
            account (str): Snowflake account name
            database (str): Database name
            warehouse (str): Warehouse name
            role (str): Role name
            
        Returns:
            connector.SnowflakeConnection: Snowflake connection object
            
        Raises:
            ConnectionError: If connection cannot be established
        """
        try:
            snowflake_con = connector.connect(
                user=f"{os.getlogin()}@brighthorizons.com",
                authenticator='externalbrowser',
                account=account,
                database=database,
                warehouse=warehouse,
                role=role
            )
            logger.info("Snowflake Connection established successfully")
            return snowflake_con
            
        except Exception as e:
            error_msg = f"Failed to establish Snowflake connection: {e}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
    
    @staticmethod
    def sql_server_authentication(
        server_name: str, 
        database_name: str, 
        autocommit: bool = True
    ) -> pyodbc.Connection:
        """
        Create a connection to SQL Server using SQL Server authentication
        
        Args:
            server_name (str): SQL Server instance name
            database_name (str): Database name
            autocommit (bool, optional): Set autocommit mode. Defaults to True.
            
        Returns:
            pyodbc.Connection: Database connection object
            
        Raises:
            ConnectionError: If connection cannot be established
        """
        try:
            connection_string = (
                r"Driver={ODBC Driver 17 for SQL Server};"
                f"Server={server_name};"
                f"Database={database_name};"
                f"UID={Creds.db_username.value};"
                f"PWD={Creds.db_password.value};"
                "Trusted_Connection=no;"
            )
            
            # Disable connection pooling before establishing connection
            pyodbc.pooling = False
            
            db_conn = pyodbc.connect(connection_string, autocommit=autocommit)
            logger.info("SQL server connection established successfully")
            return db_conn
            
        except pyodbc.Error as e:
            error_msg = f"Failed to establish SQL server connection: {e}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
    
    @staticmethod
    def close_db_connection(db_conn: Any) -> None:
        """
        Close database connection
        
        Args:
            db_conn: Database connection object to close
        """
        try:
            if db_conn:
                db_conn.close()
                logger.info("Database connection closed successfully")
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
    
    @staticmethod
    def get_db_details(
        db_info: Any, 
        connection: str
    ) -> Tuple[str, str]:
        """
        Get SQL Server connection details
        
        Args:
            db_info: DataFrame containing database information
            connection: Project name to filter database info
            
        Returns:
            Tuple[str, str]: Server name and database name
            
        Raises:
            ValueError: If connection details cannot be retrieved
        """
        try:
            filtered_info = db_info[db_info['Project'] == connection]
            
            if filtered_info.empty:
                raise ValueError(f"No database details found for project: {connection}")
                
            analytics_server = filtered_info.iloc[0]['Server']
            analytics_database = filtered_info.iloc[0]['Database']
            
            return analytics_server, analytics_database
            
        except Exception as e:
            error_msg = f"Failed to get database connection details: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e
    
    @staticmethod
    def get_db_details_snowflake(
        db_info: Any, 
        connection: str
    ) -> Tuple[str, str, str, str]:
        """
        Get Snowflake connection details
        
        Args:
            db_info: DataFrame containing database information
            connection: Project name to filter database info
            
        Returns:
            Tuple[str, str, str, str]: Server, database, warehouse, and role
            
        Raises:
            ValueError: If connection details cannot be retrieved
        """
        try:
            filtered_info = db_info[db_info['Project'] == connection]
            
            if filtered_info.empty:
                raise ValueError(f"No Snowflake details found for project: {connection}")
                
            analytics_server = filtered_info.iloc[0]['Server']
            analytics_database = filtered_info.iloc[0]['Database']
            warehouse = filtered_info.iloc[0]['Warehouse']
            role = filtered_info.iloc[0]['Role']
            
            return analytics_server, analytics_database, warehouse, role
            
        except Exception as e:
            error_msg = f"Failed to get Snowflake connection details: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e
        
    
    @classmethod
    @contextmanager
    def connection(cls, server_name: str, database_name: str, autocommit: bool = True):
        """
        Context manager for SQL Server connection using Windows authentication
        
        Args:
            server_name (str): SQL Server instance name
            database_name (str): Database name
            autocommit (bool, optional): Set autocommit mode. Defaults to True.
            
        Yields:
            pyodbc.Connection: Database connection object
        """
        conn = None
        try:
            conn = cls.create_db_connection(server_name, database_name, autocommit)
            yield conn
        finally:
            if conn:
                cls.close_db_connection(conn)
    
    @classmethod
    @contextmanager
    def snowflake_connection(cls, account: str, database: str, warehouse: str, role: str):
        """
        Context manager for Snowflake connection
        
        Args:
            account (str): Snowflake account name
            database (str): Database name
            warehouse (str): Warehouse name
            role (str): Role name
            
        Yields:
            connector.SnowflakeConnection: Snowflake connection object
        """
        conn = None
        try:
            conn = cls.create_db_connection_snowflake(account, database, warehouse, role)
            yield conn
        finally:
            if conn:
                cls.close_db_connection(conn)
    
    @classmethod
    @contextmanager
    def sql_auth_connection(cls, server_name: str, database_name: str, autocommit: bool = True):
        """
        Context manager for SQL Server connection using SQL Server authentication
        
        Args:
            server_name (str): SQL Server instance name
            database_name (str): Database name
            autocommit (bool, optional): Set autocommit mode. Defaults to True.
            
        Yields:
            pyodbc.Connection: Database connection object
        """
        conn = None
        try:
            conn = cls.sql_server_authentication(server_name, database_name, autocommit)
            yield conn
        finally:
            if conn:
                cls.close_db_connection(conn)

    def mssql_engine(server_name: str, database_name: str):

        try:
            connection_string = (
                r"Driver={ODBC Driver 17 for SQL Server};"
                f"Server={server_name};"
                f"Database={database_name};"
                "Trusted_Connection=yes;"
            )
            connection_url = URL.create( "mssql+pyodbc", query={"odbc_connect": connection_string})
            engine = create_engine(connection_url)
            conn = engine.connect().execution_options(stream_results=True)
            logger.info("DB engine created successfully")
            return conn
        except pyodbc.Error as e:
            error_msg = f"Failed to create a DB engine: {e}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        
    def synapse_engine(server_name: str, database_name: str):

        try:
            connection_string = (
                f"Driver={{ODBC Driver 17 for SQL Server}};"
                f"Server={server_name};"
                f"Database={database_name};"
                f"Authentication=ActiveDirectoryInteractive;"
                f"UID={os.getlogin()}@brighthorizons.com;"
              )

            params = urllib.parse.quote_plus(connection_string)
            engine = create_engine(f'mssql+pyodbc:///?odbc_connect={params}')
            conn = engine.connect().execution_options(stream_results=True)
            logger.info("Synapse engine created successfully")
            return conn
        except pyodbc.Error as e:
            error_msg = f"Failed to create a Synapse engine: {e}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        
    def synapse_engine_service_principal(server_name: str, database_name: str, client_id: str, client_secret: str, tenant_id: str):
        try:
            import pyodbc
            import urllib.parse
            import logging
            import os
            
            # Create connection string with Service Principal authentication
            connection_string = (
                f"Driver={{ODBC Driver 17 for SQL Server}};"
                f"Server={server_name};"
                f"Database={database_name};"
                f"Authentication=ActiveDirectoryServicePrincipal;"
                f"UID={client_id};"
                f"PWD={client_secret};"
            )
            
            # Create SQLAlchemy engine
            params = urllib.parse.quote_plus(connection_string)
            engine = create_engine(f'mssql+pyodbc:///?odbc_connect={params}')
            conn = engine.connect().execution_options(stream_results=True)
            
            logging.info("Synapse engine created successfully using Service Principal")
            return conn
        except pyodbc.Error as e:
            error_msg = f"Failed to create a Synapse engine: {e}"
            logging.error(error_msg)
            raise ConnectionError(error_msg) from e