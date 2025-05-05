import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import numpy as np
import os
import utils.custom_logger as custom_logger
import json
import glob
import time
from typing import List, Dict, Optional, Union, Any, Tuple
from datetime import datetime

class CSVFileParser:
    """
    A utility class for parsing CSV files using pandas.
    Provides methods for reading, writing, and analyzing CSV files.
    """
    def __init__(self):
        """Initialize the SQL reader with a custom logger"""
        self.log = custom_logger.customLogger()

    @staticmethod
    def read_csv(
        file_name: str,
        delimiter: str = ',',
        names: Optional[List[str]] = None,
        skip_rows: Optional[List[int]] = None,
        **kwargs
    ) -> pd.DataFrame:
        """
        Read a CSV file into a pandas DataFrame.
        
        Args:
            file_name: Path to the CSV file
            delimiter: Column separator character
            names: List of column names to use
            skip_rows: List of row indices to skip
            **kwargs: Additional arguments to pass to pd.read_csv
            
        Returns:
            A pandas DataFrame containing the CSV data
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            pd.errors.EmptyDataError: If the file is empty
            pd.errors.ParserError: If the file cannot be parsed
        """
        try:
            if not os.path.exists(file_name):
                raise FileNotFoundError(f"File not found: {file_name}")
                
            # Configure read_csv parameters based on inputs
            params = {
                'filepath_or_buffer': file_name,
                'sep': delimiter,
                'encoding': 'utf-8',
                **kwargs
            }
            
            if names:
                params['header'] = None
                params['names'] = names
                
            if skip_rows:
                params['skiprows'] = skip_rows
                
            df = pd.read_csv(**params)
            
            return df
            
        except Exception as e:
            # More specific error handling
            if isinstance(e, FileNotFoundError):
                custom_logger.customLogger().error(f"File not found: {file_name}")
            elif isinstance(e, pd.errors.EmptyDataError):
                custom_logger.customLogger().error(f"Empty file: {file_name}")
            elif isinstance(e, pd.errors.ParserError):
                custom_logger.customLogger().error(f"Parser error in file: {file_name}")
            else:
                custom_logger.customLogger().error(f"Error reading CSV file: {str(e)}")
            
            # Return empty DataFrame instead of None to maintain consistent return type
            return pd.DataFrame()

    @staticmethod
    def write_to_csv(
        data_frame: pd.DataFrame,
        file_name: str,
        index: bool = False,
        **kwargs
    ) -> bool:
        """
        Write a pandas DataFrame to a CSV or Excel file.
        
        Args:
            data_frame: The DataFrame to write
            file_name: Path for the output file
            index: Whether to include the DataFrame index in the output
            **kwargs: Additional arguments to pass to to_csv or to_excel
            
        Returns:
            True if successful, False otherwise
            
        Notes:
            Automatically determines whether to write CSV or Excel based on file extension
        """
        try:
            # Get file extension
            _, extension = os.path.splitext(file_name)
            
            # Make directory if it doesn't exist
            directory = os.path.dirname(file_name)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
            
            # Write based on file extension
            if extension.lower() in ['.xlsx', '.xls']:
                data_frame.to_excel(file_name, index=index, **kwargs)
            else:
                # Default to CSV for all other extensions
                data_frame.to_csv(file_name, index=index, **kwargs)
                
            return True
            
        except Exception as e:
            custom_logger.customLogger().error(f"Error writing to file {file_name}: {str(e)}")
            return False

    @staticmethod
    def get_header_footer_rows(file_name: str) -> List[int]:
        """
        Get row indices for header and footer of a CSV file.
        
        Args:
            file_name: Path to the CSV file
            
        Returns:
            List containing the header row index (0) and the last row index
            
        Note:
            This reads the file twice, which is inefficient for large files
        """
        try:
            # Use more efficient method to get row count
            with open(file_name, 'r', encoding='utf-8') as f:
                row_count = sum(1 for _ in f)
                
            return [0, row_count - 1]  # Return first and last row indices
            
        except Exception as e:
            custom_logger.customLogger().error(f"Error analyzing file {file_name}: {str(e)}")
            return [0, 0]  # Return default values on error
            
    @staticmethod
    def preview_csv(
        file_name: str,
        delimiter: str = ',',
        num_rows: int = 5
    ) -> pd.DataFrame:
        """
        Preview the first few rows of a CSV file.
        
        Args:
            file_name: Path to the CSV file
            delimiter: Column separator character
            num_rows: Number of rows to preview
            
        Returns:
            DataFrame containing the first num_rows rows
        """
        try:
            return pd.read_csv(
                file_name,
                sep=delimiter,
                encoding='utf-8',
                nrows=num_rows
            )
        except Exception as e:
            custom_logger.customLogger().error(f"Error previewing file {file_name}: {str(e)}")
            return pd.DataFrame()



class ExcelFileParser:
    """
    Class for handling Excel file operations including reading, writing, and processing Excel files.
    """
    
    @staticmethod
    def read_excel(
        file_name: str, 
        sheet_name: Optional[str] = None, 
        header_columns: List[str] = None, 
        skip_rows: List[int] = None
    ) -> pd.DataFrame:
        """
        Read an Excel file with configurable options for sheet name, headers, and rows to skip.
        
        Args:
            file_name (str): Path to the Excel file
            sheet_name (str, optional): Name of the sheet to read. Defaults to None (first sheet).
            header_columns (List[str], optional): Custom column names. Defaults to None.
            skip_rows (List[int], optional): Rows to skip. Defaults to None.
            
        Returns:
            pd.DataFrame: DataFrame containing the Excel data
            
        Raises:
            Exception: If an error occurs while reading the file
        """
        try:
            # Initialize default values if None
            header_columns = header_columns or []
            skip_rows = skip_rows or []
            
            # Build kwargs dictionary based on provided parameters
            kwargs = {"engine": "openpyxl"}
            
            if sheet_name is not None:
                kwargs["sheet_name"] = sheet_name
                
            if header_columns:
                kwargs["header"] = None
                kwargs["names"] = header_columns
            else:
                kwargs["header"] = 0
                
            if skip_rows:
                kwargs["skiprows"] = skip_rows
                
            # Read the Excel file with constructed parameters
            df = pd.read_excel(file_name, **kwargs)
            custom_logger.customLogger().info(f"Successfully read Excel file: {file_name}")
            return df
            
        except Exception as e:
            custom_logger.customLogger().error(f"Error reading Excel file {file_name}: {str(e)}")
            raise
    
    @staticmethod
    def create_excel_writer(file_name: str) -> pd.ExcelWriter:
        """
        Create an Excel writer object for writing to Excel files.
        
        Args:
            file_name (str): Path to the output Excel file
            
        Returns:
            pd.ExcelWriter: Excel writer object
            
        Raises:
            Exception: If an error occurs while creating the writer
        """
        try:
            excel_writer = pd.ExcelWriter(file_name, engine='xlsxwriter')
            custom_logger.customLogger().info(f"Created Excel writer for file: {file_name}")
            return excel_writer
        except Exception as e:
            custom_logger.customLogger().error(f"Error creating Excel writer for {file_name}: {str(e)}")
            raise
    
    @staticmethod
    def write_to_excel(
        data_frame: pd.DataFrame, 
        excel_writer: pd.ExcelWriter, 
        sheet_name: str, 
        column_list: Optional[List[str]] = None
    ) -> None:
        """
        Write DataFrame to an Excel sheet.
        
        Args:
            data_frame (pd.DataFrame): DataFrame to write
            excel_writer (pd.ExcelWriter): Excel writer object
            sheet_name (str): Name of the sheet to write to
            column_list (List[str], optional): List of columns to include. Defaults to None (all columns).
            
        Raises:
            Exception: If an error occurs while writing to the Excel file
        """
        try:
            # Filter columns if specified
            if column_list:
                data_frame = data_frame[column_list]
                
            data_frame.to_excel(excel_writer, sheet_name=sheet_name, index=False)
            custom_logger.customLogger().info(f"Data written to sheet: {sheet_name}")
        except Exception as e:
            custom_logger.customLogger().error(f"Error writing to sheet {sheet_name}: {str(e)}")
            raise
    
    @staticmethod
    def save_excel_writer(excel_writer: pd.ExcelWriter) -> None:
        """
        Save and close the Excel writer.
        
        Args:
            excel_writer (pd.ExcelWriter): Excel writer object to save
            
        Raises:
            Exception: If an error occurs while saving the Excel file
        """
        try:
            #excel_writer.save()
            excel_writer.close()
            custom_logger.customLogger().info("Excel file saved successfully")
        except Exception as e:
            custom_logger.customLogger().error(f"Error saving Excel file: {str(e)}")
            raise
    
    @staticmethod
    def get_sheet_name(row: pd.Series, column_name: str) -> Optional[str]:
        """
        Extract sheet name from a DataFrame row.
        
        Args:
            row (pd.Series): DataFrame row
            column_name (str): Column name containing the sheet name
            
        Returns:
            Optional[str]: Sheet name or None if not found
        """
        try:
            sheet_name = row.get(column_name)
            if sheet_name and pd.notna(sheet_name):
                return str(sheet_name)
            return None
        except Exception as e:
            custom_logger.customLogger().warning(f"Error extracting sheet name from column {column_name}: {str(e)}")
            return None
    
    @staticmethod
    def get_src_sheet_name(row: pd.Series) -> Optional[str]:
        """
        Get source sheet name from a DataFrame row.
        
        Args:
            row (pd.Series): DataFrame row
            
        Returns:
            Optional[str]: Source sheet name or None if not found
        """
        return ExcelFileParser.get_sheet_name(row, 'src_sheet_name')
    
    @staticmethod
    def get_tgt_sheet_name(row: pd.Series) -> Optional[str]:
        """
        Get target sheet name from a DataFrame row.
        
        Args:
            row (pd.Series): DataFrame row
            
        Returns:
            Optional[str]: Target sheet name or None if not found
        """
        return ExcelFileParser.get_sheet_name(row, 'tgt_sheet_name')
    
    @staticmethod
    def get_header_footer_rows(file_name: str) -> List[int]:
        """
        Get row indices for header and footer (first and last rows).
        
        Args:
            file_name (str): Path to the Excel file
            
        Returns:
            List[int]: List containing indices of header and footer rows
        """
        try:
            df = pd.read_excel(file_name, engine="openpyxl")
            return [0, len(df)]
        except Exception as e:
            custom_logger.customLogger().error(f"Error determining header/footer rows for {file_name}: {str(e)}")
            return []
    
    @staticmethod
    def get_skip_rows(file_name: str, row: pd.Series) -> List[int]:
        """
        Determine which rows to skip based on configuration.
        
        Args:
            file_name (str): Path to the Excel file
            row (pd.Series): DataFrame row containing skip configuration
            
        Returns:
            List[int]: List of row indices to skip
        """
        try:
            skip_rows = row.get('skip_rows')
            if pd.notna(skip_rows):
                if skip_rows == 'Default':
                    return ExcelFileParser.get_header_footer_rows(file_name)
                elif isinstance(skip_rows, str):
                    # Safely evaluate string representation of list
                    import ast
                    return ast.literal_eval(skip_rows)
            return []
        except Exception as e:
            custom_logger.customLogger().warning(f"Error determining skip rows: {str(e)}")
            return []
    
    @staticmethod
    def get_header_columns(row: pd.Series) -> List[str]:
        """
        Extract header column names from configuration.
        
        Args:
            row (pd.Series): DataFrame row containing header configuration
            
        Returns:
            List[str]: List of column names
        """
        try:
            header_columns = row.get('header_columns')
            if pd.notna(header_columns) and isinstance(header_columns, str):
                # Safely evaluate string representation of list
                import ast
                return ast.literal_eval(header_columns)
            return []
        except Exception as e:
            custom_logger.customLogger().warning(f"Error determining header columns: {str(e)}")
            return []

    @staticmethod
    def get_filters(row: pd.Series) -> List[str]:
        """
        Extract header column names from configuration.
        
        Args:
            row (pd.Series): DataFrame row containing header configuration
            
        Returns:
            List[str]: List of column names
        """
        try:
            filters = row.get('Filters')
            if pd.notna(filters) and isinstance(filters, str):
                # Safely evaluate string representation of list
                import ast
                return ast.literal_eval(filters)
            return []
        except Exception as e:
            custom_logger.customLogger().warning(f"Error determining Filters: {str(e)}")
            return []    
            
    @staticmethod
    def process_excel_files(config_df: pd.DataFrame, input_dir: str = "", output_dir: str = "") -> Dict[str, Any]:
        """
        Process multiple Excel files based on configuration DataFrame.
        
        Args:
            config_df (pd.DataFrame): Configuration with file paths and settings
            input_dir (str, optional): Input directory prefix. Defaults to "".
            output_dir (str, optional): Output directory prefix. Defaults to "".
            
        Returns:
            Dict[str, Any]: Status of processing operations
        """
        results = {
            "processed_files": 0,
            "errors": 0,
            "details": []
        }
        
        try:
            for _, row in config_df.iterrows():
                try:
                    src_file = f"{input_dir}{row['src_file']}" if 'src_file' in row else None
                    tgt_file = f"{output_dir}{row['tgt_file']}" if 'tgt_file' in row else None
                    
                    if not src_file:
                        continue
                        
                    # Get parameters from configuration
                    src_sheet = ExcelFileParser.get_src_sheet_name(row)
                    skip_rows = ExcelFileParser.get_skip_rows(src_file, row)
                    header_cols = ExcelFileParser.get_header_columns(row)
                    
                    # Read source file
                    df = ExcelFileParser.read_excel(src_file, src_sheet, header_cols, skip_rows)
                    
                    # Process data if needed
                    if 'transform_function' in row and callable(row['transform_function']):
                        df = row['transform_function'](df)
                    
                    # Write to target if specified
                    if tgt_file:
                        tgt_sheet = ExcelFileParser.get_tgt_sheet_name(row) or "Sheet1"
                        writer = ExcelFileParser.create_excel_writer(tgt_file)
                        ExcelFileParser.write_to_excel(df, writer, tgt_sheet)
                        ExcelFileParser.save_excel_writer(writer)
                    
                    results["processed_files"] += 1
                    results["details"].append({"file": src_file, "status": "success"})
                    
                except Exception as e:
                    results["errors"] += 1
                    results["details"].append({"file": src_file, "status": "error", "message": str(e)})
                    custom_logger.customLogger().error(f"Error processing file {src_file}: {str(e)}")
            
            return results
            
        except Exception as e:
            custom_logger.customLogger().error(f"Error in process_excel_files: {str(e)}")
            results["errors"] += 1
            results["details"].append({"status": "error", "message": str(e)})
            return results

