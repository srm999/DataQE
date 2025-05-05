import pandas as pd
import dask.dataframe as dd
import numpy as np
import os
import ast
import re
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.csv as csv
import json
from typing import Dict, List, Tuple, Optional, Union, Any
from datetime import datetime
from refactored.adl_datareader import MyAzureReader
from refactored.dataverse_datareader import MyDataverseReader
from core.file_parsing import CSVFileParser, ExcelFileParser
from core.db_connection import DatabaseConnection
from core.sql_reader import SQLFileReader
from core.data_processing import *
from utils.custom_logger import customLogger

class DataRetriever:
    """
    Handles retrieval of data from different sources (Excel, CSV, SQL, Snowflake)
    """
    
    def __init__(self, db_info: Dict, base_filepath: str):
        from utils.custom_logger import customLogger
        self.log = customLogger()
        self.db_info = db_info
        self.base_filepath = base_filepath
        self.no_count = """ SET NOCOUNT ON; SET ANSI_WARNINGS OFF; SET ARITHABORT ON; SET ANSI_NULLS ON; SET ANSI_WARNINGS ON; """

        # Initialize components
        self.filereader = SQLFileReader()
        self.dbconnection = DatabaseConnection
        self.azurereader = MyAzureReader()
        self.dataversereader= MyDataverseReader()
    
    def get_config_params(self, row: Dict[str, Any], is_source: bool) -> Dict[str, Any]:
        """Extract and prepare configuration parameters."""
        prefix = "SRC" if is_source else "TGT"
        connection_type = row[f"{prefix}_Connection"] if f"{prefix}_Connection" in row else None
        data_file = row[f"{prefix}_Data_File"] if f"{prefix}_Data_File" in row else None
        pk_col_val = row['pk_columns'] if 'pk_columns' in row else None
        filters = row['Filters'] if 'Filters' in row else None
        
        # Handle NaN values safely
        params = {
            'connection_type': connection_type,
            'data_file': str(data_file) if not pd.isna(data_file) else None,
            'file_path': self.base_filepath + (str(data_file) if not pd.isna(data_file) else ""),
            'is_source': is_source,
            'relative_file_path': str(data_file) if not pd.isna(data_file) else None,
        }
        
        # Safely handle pk_columns
        if pk_col_val is not None and not pd.isna(pk_col_val):
            try:
                params['pk_columns'] = ast.literal_eval(pk_col_val)
            except (ValueError, SyntaxError):
                # If it's not a valid Python literal, treat as a string
                params['pk_columns'] = [col.strip() for col in str(pk_col_val).split(',')]
        else:
            params['pk_columns'] = []
        
        # Safely handle filters
        if filters is not None and not pd.isna(filters):
            try:
                params['filters'] = ast.literal_eval(filters)
            except (ValueError, SyntaxError):
                # If it's not a valid Python literal, use None
                params['filters'] = None
        else:
            params['filters'] = None
            
        return params

    def get_data(self, row: Dict[str, Any], is_source: bool = True) -> Optional[pd.DataFrame]:
        """
        Enhanced method to retrieve data from source or target with performance optimizations.
        
        Args:
            row: Configuration row with connection details
            is_source: If True, retrieves source data; otherwise retrieves target data
            
        Returns:
            DataFrame containing the retrieved data or None if an error occurs
        """
        try:
            self.log.info(f"Fetching {'source' if is_source else 'target'} data.")
            
            params = self.get_config_params(row, is_source)
            conn_type = params['connection_type']
            file_name = params['file_path']
            relative_file_name = params['relative_file_path']
            filters = params['filters']
            
            # Use strategy pattern to handle different data sources
            if conn_type == 'Excel':
                df = self.read_excel(row, file_name, is_source)
            elif conn_type == 'CSV':
                df = self.read_csv(row, file_name)
            elif 'PARQUET' in conn_type:
                df = self.azurereader.read_blob_from_azure(row=row,azure_path=relative_file_name , file_format='parquet',filters=filters)
            elif 'DELTA' in conn_type:
                df = self.azurereader.read_blob_from_azure(row=row, azure_path=relative_file_name , file_format='delta',filters=filters)
            elif 'SNOWFLAKE' in conn_type:
                df = self.read_snowflake(row, file_name, conn_type)
            elif 'D365' in conn_type:
                df = self.dataversereader.read_dataverse_table_data (relative_file_name,self.db_info, conn_type) 
            elif 'CID' in conn_type:
                df = self.dataversereader.read_cid_customerprofile_data (relative_file_name, self.db_info, conn_type)    
            elif 'SYNAPSE' in conn_type:
                df = self.read_synapse_sql(row, file_name, conn_type)        
            else:  # SQL Server or other database
                df = self.read_sql(row, file_name, conn_type)
            
            # Sort the dataframe if primary key columns are specified
            if params['pk_columns']:
                column_map ={col.lower(): col for col in df.columns}

                actual_columns = []
                for pk_col in params['pk_columns']:
                    pk_col_lower = pk_col.lower()
                    if pk_col_lower in column_map:
                        actual_columns.append(column_map[pk_col_lower])
                    else:
                        continue
                if actual_columns:
                    return df.sort_values(by=actual_columns, ascending=False)
                else:
                 return df[sorted(df.columns)]
            else:
                 return df[sorted(df.columns)]
                
        except Exception as e:
            self.log.error(f"Failed: get {'source' if is_source else 'target'} data - {str(e)}")
            return None

    def read_excel(self, row: Dict[str, Any], file_name: str, is_source: bool) -> pd.DataFrame:
        """Read data from Excel files with optimizations."""
        sheet_name = ExcelFileParser.get_src_sheet_name(row) if is_source else ExcelFileParser.get_tgt_sheet_name(row)
        skip_rows = ExcelFileParser.get_skip_rows(file_name, row)
        header_columns = ExcelFileParser.get_header_columns(row)
        
        # Use engine='openpyxl' for xlsx files, 'xlrd' for xls
        engine = 'openpyxl' if file_name.endswith('.xlsx') else 'xlrd'
        
        # For large Excel files, read in chunks
        if os.path.getsize(file_name) > 100 * 1024 * 1024:  # 100 MB
            # Read in chunks and concatenate
            chunk_size = 100000  # Adjust based on your memory constraints
            chunks = []
            for chunk in pd.read_excel(
                file_name, 
                sheet_name=sheet_name, 
                skiprows=skip_rows,
                usecols=header_columns if header_columns else None, 
                engine=engine,
                chunksize=chunk_size
            ):
                chunks.append(chunk)
            return pd.concat(chunks, ignore_index=True)
        else:
            return ExcelFileParser.read_excel(file_name, sheet_name, header_columns, skip_rows)

    def read_csv(self, row: Dict[str, Any], file_name: str) -> pd.DataFrame:
        """Read data from CSV files with optimizations."""
        delimiter = row.get('Delimiter', ',')
        header_columns_value = self._safe_parse_json(row.get('header_columns'), default=False)
        
        # For large CSV files, use PyArrow or Dask
        if os.path.getsize(file_name) > 500 * 1024 * 1024:  # 500 MB
            try:
                # Try PyArrow first for faster parsing
                parse_options = csv.ParseOptions(delimiter=delimiter)
                table = csv.read_csv(file_name, parse_options=parse_options)
                return table.to_pandas()
            except Exception as e:
                self.log.warning(f"PyArrow CSV reading failed, falling back to Dask: {str(e)}")
                # Fall back to Dask for out-of-memory situations
                ddf = dd.read_csv(
                    file_name, 
                    delimiter=delimiter,
                    header=0 if header_columns_value else None,
                    assume_missing=True
                )
                return ddf.compute()
        
        # Standard CSV reading for smaller files
        if header_columns_value:
            if row.get('skip_rows') == 'Default':
                skip_rows = CSVFileParser.get_header_footer_rows(file_name)
            else:
                skip_rows = self._safe_parse_json(row.get('skip_rows'), default=0)
            
            return CSVFileParser.read_csv(file_name, delimiter, header_columns_value, skip_rows)
        else:
            return CSVFileParser.read_csv(file_name, delimiter)

           
    
    def read_snowflake(self, row: Dict[str, Any], file_name: str, conn_type: str) -> pd.DataFrame:
        """Read data from Snowflake with performance monitoring."""
        start = datetime.now()
        db_conn = self.get_db_connection_snowflake(conn_type)
        df = self.filereader.read_sql_query_with_cursor(
                file_name, 
                db_conn)
        self.dbconnection.close_db_connection(db_conn)
        end = datetime.now()
        self.log.info(f"{row.get('SRC_Data_File' if row.get('SRC_Connection') == conn_type else 'TGT_Data_File')} load time -- {end-start}")
        return df

    def read_sql(self, row: Dict[str, Any], file_name: str, conn_type: str) -> pd.DataFrame:
        """Read data from SQL databases with performance optimizations."""
        start = datetime.now()
        
        db_conn = self.get_db_connection(conn_type)
        df = self.filereader.read_sqlquery_in_chunks(
                file_name, 
                db_conn, 
                self.no_count)
        end = datetime.now()
        self.log.info(f"{row.get('SRC_Data_File' if row.get('SRC_Connection') == conn_type else 'TGT_Data_File')} load time -- {end-start}")
        return df

    def get_db_connection(self, connection_type: str):
        """Get database connection for SQL databases"""
        try:
            analytics_server, analytics_database = self.dbconnection.get_db_details(self.db_info, connection_type)
            #db_conn = self.dbconnection.create_db_connection(analytics_server, analytics_database)
            db_conn = self.dbconnection.mssql_engine(analytics_server, analytics_database)
            return db_conn
        except Exception as e:
            self.log.error(f"Failed: Get database connection - {e}")
            raise ConnectionError(f"Failed to connect to {connection_type}: {e}")
            
    def get_db_connection_snowflake(self, connection_type: str):
        """Get database connection for Snowflake"""
        try:
            account, analytics_database, warehouse, role = self.dbconnection.get_db_details_snowflake(self.db_info, connection_type)
            self.log.info(f" Account - {account} , ADB - {analytics_database}, WH - {warehouse},role -{role} ")
            db_conn = self.dbconnection.create_db_connection_snowflake(account, analytics_database, warehouse, role)
            return db_conn
        except Exception as e:
            self.log.error(f"Failed: Get Snowflake database connection - {e}")
            raise ConnectionError(f"Failed to connect to Snowflake {connection_type}: {e}")
        
    def read_synapse_sql(self, row: Dict[str, Any], file_name: str, conn_type: str) -> pd.DataFrame:
        """Read data from SQL databases with performance optimizations."""
        start = datetime.now()
        
        db_conn = self.get_synapse_connection(conn_type)
        df = self.filereader.read_sqlquery_in_chunks(
                file_name, 
                db_conn, 
                self.no_count)
        end = datetime.now()
        self.log.info(f"{row.get('SRC_Data_File' if row.get('SRC_Connection') == conn_type else 'TGT_Data_File')} load time -- {end-start}")
        return df

    def get_synapse_connection(self, connection_type: str):
        """Get database connection for SQL databases"""
        try:
            analytics_server, analytics_database = self.dbconnection.get_db_details(self.db_info, connection_type)
            db_conn = self.dbconnection.synapse_engine(analytics_server, analytics_database)
            return db_conn
        except Exception as e:
            self.log.error(f"Failed: Get database connection - {e}")
            raise ConnectionError(f"Failed to connect to {connection_type}: {e}")
    
    


class DataTransformer:
    """
    Handles transformations on dataframes to make them comparable
    """
    
    def __init__(self):
        self.log = custom_logger.customLogger()
    
    def convert_date_fields(self, src_df: pd.DataFrame, tgt_df: pd.DataFrame, 
                          date_fields: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Convert columns to datetime format in both dataframes.
        
        Args:
            src_df: Source dataframe
            tgt_df: Target dataframe
            date_fields: List of column names to convert
            
        Returns:
            Tuple of (transformed_src_df, transformed_tgt_df)
        """
        try:
            # Convert date fields in source dataframe
            src_df[date_fields] = src_df[date_fields].apply(pd.to_datetime, errors='coerce')
            
            # Convert date fields in target dataframe
            tgt_df[date_fields] = tgt_df[date_fields].apply(pd.to_datetime, errors='coerce')
            
            return src_df, tgt_df
            
        except Exception as e:
            self.log.error(f"Failed: date fields conversion - {e}")
            raise ValueError(f"Date field conversion failed: {e}")
    
    def convert_type_fields(self, src_df: pd.DataFrame, tgt_df: pd.DataFrame, 
                          type_fields: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Convert columns to float then string in both dataframes.
        
        Args:
            src_df: Source dataframe
            tgt_df: Target dataframe
            type_fields: List of column names to convert
            
        Returns:
            Tuple of (transformed_src_df, transformed_tgt_df)
        """
        try:
            # Convert type fields in source dataframe
            src_df[type_fields] = src_df[type_fields].astype(float).astype(str)
            
            # Convert type fields in target dataframe
            tgt_df[type_fields] = tgt_df[type_fields].astype(float).astype(str)
            
            return src_df, tgt_df
            
        except Exception as e:
            self.log.error(f"Failed: type conversion fields - {e}")
            raise ValueError(f"Type conversion failed: {e}")
    
   
    def process_percentage_fields(self, src_df: pd.DataFrame, tgt_df: pd.DataFrame, 
                                row: Dict[str, Any]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Handle percentage fields in both dataframes for consistent comparison.
        
        Args:
            src_df: Source dataframe
            tgt_df: Target dataframe
            row: Configuration row with metadata
            
        Returns:
            Tuple of (transformed_src_df, transformed_tgt_df)
        """
        try:
            # Parse percentage columns safely
            percentage_columns = json.loads(row['Percentage_Fields']) if row['Percentage_Fields'] else []
            
            if not percentage_columns:
                return src_df, tgt_df
                
            # Extract source and target dataframes for processing
            source_df = src_df[percentage_columns].copy()
            target_df = tgt_df[percentage_columns].copy()
            
            # Process source dataframe percentage columns
            source_df = source_df.apply(
                lambda x: self._convert_percentage_field(x, row['SRC_Connection'] == 'Excel')
            )
            
            # Process target dataframe percentage columns
            target_df = target_df.apply(
                lambda x: self._convert_percentage_field(x, row['TGT_Connection'] == 'Excel')
            )
            
            # Update the original dataframes with processed columns
            src_df[percentage_columns] = source_df
            tgt_df[percentage_columns] = target_df
            
            return src_df, tgt_df
            
        except Exception as e:
            self.log.error(f"Failed: Handling Percentage Fields - {e}")
            raise ValueError(f"Percentage field processing failed: {e}")
    
    def _convert_percentage_field(self, col, multiply_with_hundred: bool) -> pd.Series:
        """
        Convert percentage values for consistent comparison.
        
        Args:
            col: Column to process
            multiply_with_hundred: Whether to multiply values by 100
            
        Returns:
            Processed column
        """
        try:
            # Check if column contains percentage symbols
            if col.astype(str).str.contains('%').any():
                # Remove percentage symbols
                col = col.str.replace('%', '')
            else:
                if multiply_with_hundred:
                    # Multiply by 100 and round to 2 decimal places
                    col = ((col.astype(float)) * 100).round(decimals=2).astype(str)
                else:
                    # Just round to 2 decimal places
                    col = col.astype(float).round(decimals=2).astype(str)
                    
            return col
            
        except Exception as e:
            self.log.error(f"Failed: percentage fields conversion - {e}")
            raise ValueError(f"Percentage field conversion failed: {e}")


class DataValidationFramework:
    """
    Main framework for data validation process
    """
    
    def __init__(self, config_file: str, db_filepath: str):
        """
        Initialize the data validation framework.
        
        Args:
            config_file: Path to configuration Excel file
            db_filepath: Base path for data files
        """
        self.config_file = config_file
        self.db_filepath = db_filepath
        self.log = custom_logger.customLogger()
        self.current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Read configuration from Excel
        self.src_tgt_data_info, self.db_info = self._read_configuration()
        
        # Initialize components
        self.retriever = DataRetriever(self.db_info, self.db_filepath)
        self.transformer = DataTransformer()
        
    def _read_configuration(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Read and parse configuration from Excel file"""
        try:
            # Default sheet names
            sheetnames = ['SRC_TGT_SQL_Pairs', 'Connections']
            
            # Set pandas to show all columns
            pd.set_option('display.max_columns', None)
            
            # Read the Excel file
            df = ExcelFileParser.read_excel(self.config_file, sheetnames)
            
            # Extract data and connection info
            data_df = df[sheetnames[0]]
            db_info = df[sheetnames[1]]
            
            # Filter to only enabled tests
            src_tgt_data_info = data_df[data_df['Test_YN'] == 'Y']
            
            return src_tgt_data_info, db_info
            
        except Exception as e:
            self.log.error(f"Failed: Reading test query pairs excel file - {e}")
            raise ValueError(f"Configuration loading failed: {e}")
            
    def validate_data_pair(self, row_index: int) -> Dict[str, Any]:
        """
        Validate a single data pair based on configuration.
        
        Args:
            row_index: Index of the pair to validate in configuration
            
        Returns:
            Dictionary with validation results
        """
        try:
            # Get configuration for this test pair
            row = self.src_tgt_data_info.iloc[row_index].to_dict()
            
            # Get source and target data
            src_df = self.retriever.get_data(row, is_source=True)
            tgt_df = self.retriever.get_data(row, is_source=False)
            
            if src_df is None or tgt_df is None:
                return {
                    "status": "Failed",
                    "message": "Failed to retrieve source or target data",
                    "test_id": row.get("Test_ID", "Unknown")
                }
                
            # Apply transformations if needed
            self._apply_transformations(src_df, tgt_df, row)
            
            # Compare column structure
            cols_match, src_only_cols, tgt_only_cols = self.comparator.compare_column_structure(src_df, tgt_df)
            
            if not cols_match:
                return {
                    "status": "Failed",
                    "message": "Column structure mismatch",
                    "test_id": row.get("Test_ID", "Unknown"),
                    "source_only_columns": src_only_cols,
                    "target_only_columns": tgt_only_cols
                }
                
            # Compare data
            output_file = f"{self.db_filepath}comparison_results_{row.get('Test_ID', 'Unknown')}_{self.current_time}.xlsx"
            diff_df, excel_writer = self.comparator.compare_dataframes(src_df, tgt_df, row, output_file)
            
            if len(diff_df) > 0:
                # Save differences if found
                if excel_writer:
                    diff_df.to_excel(excel_writer, sheet_name='Differences')
                    excel_writer.close()
                    
                return {
                    "status": "Failed",
                    "message": "Data mismatch",
                    "test_id": row.get("Test_ID", "Unknown"),
                    "differences_count": len(diff_df),
                    "output_file": output_file
                }
            else:
                return {
                    "status": "Success",
                    "message": "Data match",
                    "test_id": row.get("Test_ID", "Unknown")
                }
                
        except Exception as e:
            self.log.error(f"Failed: Data validation for row {row_index} - {e}")
            return {
                "status": "Error",
                "message": str(e),
                "test_id": self.src_tgt_data_info.iloc[row_index].get("Test_ID", "Unknown") if row_index < len(self.src_tgt_data_info) else "Unknown"
            }
            
    def _apply_transformations(self, src_df: pd.DataFrame, tgt_df: pd.DataFrame, row: Dict[str, Any]) -> None:
        """Apply necessary transformations to make dataframes comparable

            Args:
        src_df (pd.DataFrame): Source DataFrame
        tgt_df (pd.DataFrame): Target DataFrame
        row_index: Index of the pair to validate in configuration
        
        Returns:
            Tuple[pd.DataFrame, pd.DataFrame]: Transformed source and target DataFrames
        """
        try:
            # Standardize column names
            #src_df = self.transformer.standardize_column_names(src_df)
            #tgt_df = self.transformer.standardize_column_names(tgt_df)
            
            # Convert date fields if specified
            if row.get('Date_Fields'):
                date_fields = json.loads(row['Date_Fields']) if row['Date_Fields'] else []
                if date_fields:
                    src_df, tgt_df = self.transformer.convert_date_fields(src_df, tgt_df, date_fields)
            
            # Convert type fields if specified
            if row.get('Type_Convert_Fields'):
                type_fields = json.loads(row['Type_Convert_Fields']) if row['Type_Convert_Fields'] else []
                if type_fields:
                    src_df, tgt_df = self.transformer.convert_type_fields(src_df, tgt_df, type_fields)
            
            # Process percentage fields if specified
            if row.get('Percentage_Fields'):
                src_df, tgt_df = self.transformer.process_percentage_fields(src_df, tgt_df, row)
            
            return src_df, tgt_df
        except Exception as e:
            self.log.error(f"Error in applying transformations to DataFrames: {e}")
        raise    


