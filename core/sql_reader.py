import os
import pandas as pd
import pyodbc
from typing import Optional, Union, Dict, Any
from contextlib import contextmanager
import datetime  
from utils import custom_logger

class SQLFileReader:
    """
    A utility class for executing SQL queries from files and parsing results.
    Supports multiple database types including ODBC and Snowflake.
    """
    
    def __init__(self):
        """Initialize the SQL reader with a custom logger"""
        self.log = custom_logger.customLogger()
        

    def get_sql_query(self,filename: str) -> Optional[str]:
        """
        Read SQL query from a file.
        
        Args:
            filename: Path to the SQL file
            
        Returns:
            The SQL query as a string or None if an error occurs
            
        Raises:
            FileNotFoundError: If the file does not exist
        """
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"SQL file not found: {filename}")
                
            with open(filename, 'r') as sql_file:
                return sql_file.read()
                
        except FileNotFoundError as e:
            self.log.error(f"File not found: {filename}")
            return None
        except Exception as e:
            self.log.error(f"Error reading SQL file {filename}: {str(e)}")
            return None
    
    @contextmanager
    def cursor_manager(self, connection):
        """
        Context manager for database cursors.
        
        Args:
            connection: Database connection object
            
        Yields:
            A cursor object that will be automatically closed
        """
        cursor = connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()
    
    def handle_db_exception(self, exception: Exception, query_info: str = "") -> None:
        """
        Centralized exception handler for database operations.
        
        Args:
            exception: The exception that was raised
            query_info: Additional information about the query being executed
        """
        # Handle pyodbc specific exceptions
        if isinstance(exception, pyodbc.Error):
            error_type = type(exception).__name__
            self.log.error(f"{error_type} occurred with query {query_info}: {str(exception)}")
            
            # Only add warning for specific error types
            if isinstance(exception, (pyodbc.OperationalError, pyodbc.DataError, 
                                     pyodbc.IntegrityError, pyodbc.ProgrammingError)):
                self.log.warning(f"Warning: {str(exception)}")
        else:
            # Generic exception handling
            self.log.error(f"Unexpected error with query {query_info}: {str(exception)}")
    
    def read_sqlquery(
        self, 
        filename: str, 
        db_conn, 
        no_count: str = "SET NOCOUNT ON;", 
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[pd.DataFrame]:
        """
        Execute a SQL query from a file using pandas read_sql_query.
        
        Args:
            filename: Path to the SQL file
            db_conn: Database connection object
            no_count: SQL command to prepend to the query (default: "SET NOCOUNT ON;")
            params: Parameters to pass to the query
            
        Returns:
            DataFrame containing the query results or None if an error occurs
        """
        try:
            query = self.get_sql_query(filename)
            if query is None:
                return None
                
            # Combine the NOCOUNT directive with the query
            full_query = f"{no_count} {query}" if no_count else query
            
            # Use parameters if provided
            if params:
                return pd.read_sql_query(sql=full_query, con=db_conn, params=params)
            else:
                return pd.read_sql_query(sql=full_query, con=db_conn)
                
        except Exception as e:
            self.handle_db_exception(e, f"from file {filename}")
            return None
    
    def read_sql_query_with_cursor(
        self, 
        filename: str, 
        db_conn, 
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[pd.DataFrame]:
        """
        Execute a SQL query from a file using a cursor and convert results to DataFrame.
        
        Args:
            filename: Path to the SQL file
            db_conn: Database connection object
            no_count: SQL command to prepend to the query (default: "SET NOCOUNT ON;")
            params: Parameters to pass to the query
            
        Returns:
            DataFrame containing the query results or None if an error occurs
        """
        query = self.get_sql_query(filename)
        if query is None:
            return None
            
        # Combine the NOCOUNT directive with the query
        #full_query = f"{no_count} {query}" if no_count else query
        
        with self.cursor_manager(db_conn) as cursor:
            try:
                # Execute with or without parameters
                if params:
                    rows = cursor.execute(query, params)
                else:
                    rows = cursor.execute(query)
                
                # Extract column names from cursor description
                if rows.description:
                    headers = [col[0] for col in rows.description]
                    # Convert results to DataFrame
                    return pd.DataFrame((tuple(t) for t in rows), columns=headers)
                else:
                    # Handle case with no results
                    return pd.DataFrame()
                    
            except Exception as e:
                self.handle_db_exception(e, f"from file {filename}")
                return None
    
    def read_snowflake_sql_query(
        self, 
        filename: str, 
        db_conn, 
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[pd.DataFrame]:
        """
        Execute a SQL query from a file using a Snowflake cursor.
        
        Args:
            filename: Path to the SQL file
            db_conn: Snowflake database connection object
            params: Parameters to pass to the query
            
        Returns:
            DataFrame containing the query results or None if an error occurs
        """
        query = self.get_sql_query(filename)
        if query is None:
            return None
            
        with self.cursor_manager(db_conn) as cursor:
            
            try:
                # Execute with or without parameters
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                    
                # Fetch all results as a pandas DataFrame
                return cursor.fetch_pandas_all()
                
            except Exception as e:
                self.log.error(f"Snowflake query error with file {filename}: {str(e)}")
                return None

    def read_sqlquery_in_chunks(self, 
                            filename: str,
                            db_conn,
                            no_count: str = "SET NOCOUNT ON;",
                            chunksize: int = 100000) -> Optional[pd.DataFrame]:
        """
        Execute a SQL query from a file using pandas read_sql_query.
        
        Args:
            filename: Path to the SQL file
            db_conn: Database connection object
            no_count: SQL command to disable row count messages
            chunksize: Number of rows to process at once
            
        Returns:
            DataFrame containing the query results or None if an error occurs
        """
        try:
            query = self.get_sql_query(filename)
            if query is None:
                self.log.warning(f"Failed to get SQL query from {filename}")
                return None
                
               
            # Create an empty DataFrame to store all results
            #all_data = pd.DataFrame()
            chunks =[]
            total_rows = 0
            chunk_count = 0
            
            # Iterate through chunks and append them
            for chunk_df in pd.read_sql_query(query, db_conn, chunksize=chunksize):
                chunk_count += 1
                chunk_rows = len(chunk_df)
                total_rows += chunk_rows
                #self.log.info(f"Processing chunk {chunk_count} with {len(chunk_df)} rows")
                
                chunks.append(chunk_df)

                if chunk_count % 100 == 0:
                    self.log.info(f"Processed {chunk_count} chunks, total rows so far {total_rows} rows")

                
            self.log.info(f"Concatenating {chunk_count} chunks with total: {total_rows} rows")
            all_data = pd.concat(chunks,ignore_index=True)
            self.log.info(f"Completed processing {chunk_count} chunks with total rows: {len(all_data)} rows")
            return all_data
            
        except Exception as e:
            self.log.error(f"Failed: read_sqlquery_in_chunks - {e}")
            return None
        
    def read_snowflake_sql_query_in_chunks(self,
                                      filename: str,
                                      db_conn,
                                      no_count: str = "SET NOCOUNT ON;",
                                      chunk_size: int = 100000) -> Optional[pd.DataFrame]:
        """
        Execute a SQL query from a file using Snowflake cursor and process results in chunks.
        
        Args:
            filename: Path to the SQL file
            db_conn: Database connection object
            no_count: SQL command to disable row count messages (Note: may not apply to Snowflake)
            chunk_size: Number of rows to fetch in each batch
            
        Returns:
            DataFrame containing the query results or None if an error occurs
        """
        db_cur = None
        try:
            query = self.get_sql_query(filename)
            if query is None:
                self.log.warning(f"Failed to get SQL query from {filename}")
                return None
                
            # Apply NOCOUNT if needed for Snowflake
            #if no_count and "SET NOCOUNT" in no_count:
                #self.log.info("Note: SET NOCOUNT may not apply to Snowflake, but executing query as requested")
                #query = f"{no_count}\n{query}"
                
            db_cur = db_conn.cursor()
            chunks = []
            total_rows = 0
            
            # Execute query
            self.log.info(f"Executing Snowflake query from {filename}")
            db_cur.execute(query)
            
            # Get column names from cursor description
            columns = [col[0] for col in db_cur.description]
            
            # Process in chunks
            chunk_num = 0
            while True:
                chunk_num += 1
                tgt_data = db_cur.fetchmany(chunk_size)
                
                if not tgt_data:
                    break
                    
                # Create DataFrame from chunk
                chunk_df = pd.DataFrame(tgt_data, columns=columns)
                
                # Process datetime columns
                for col in chunk_df.columns:
                    if (pd.api.types.is_datetime64_any_dtype(chunk_df[col]) or 
                        pd.api.types.is_timedelta64_dtype(chunk_df[col]) or
                        chunk_df[col].dtype == 'object' and chunk_df[col].apply(lambda x: isinstance(x, (datetime.datetime, datetime.date))).any()):
                        chunk_df[col] = pd.to_datetime(chunk_df[col], errors='coerce', utc=True)
                
                chunks.append(chunk_df)
                rows_in_chunk = len(chunk_df)
                total_rows += rows_in_chunk
                self.log.info(f"Processed chunk {chunk_num} with {rows_in_chunk} rows")
            
            # Combine all chunks
            if chunks:
                tgt_df = pd.concat(chunks, ignore_index=True)
                self.log.info(f"Created DataFrame with {len(tgt_df)} rows from {chunk_num} chunks")
                return tgt_df
            else:
                self.log.info("Query returned no data")
                return pd.DataFrame(columns=columns)
                
        except Exception as e:
            self.log.error(f"Failed: read_snowflake_sql_query_in_chunks - {e}")
            return None
            
        finally:
            # Ensure cursor is closed even if exception occurs
            if db_cur is not None:
                try:
                    db_cur.close()
                except Exception as e:
                    self.log.warning(f"Failed to close cursor: {e}")