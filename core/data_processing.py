import pandas as pd
import pyarrow as pa
import numpy as np
from datetime import datetime
import sys
from typing import Tuple, Optional, Dict, Any, List, Union
from core.file_parsing import CSVFileParser, ExcelFileParser
from utils import custom_logger

def convert_bytearray_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert bytearray columns to UTF-8 strings.
    
    Args:
        df (pd.DataFrame): Input DataFrame with potential bytearray columns
        
    Returns:
        pd.DataFrame: DataFrame with bytearray columns converted to strings
    """
    try:
        # More efficient approach using vectorized operations where possible
        for col in df.columns:
            # Check if any value in the column is a bytearray
            if df[col].apply(lambda x: isinstance(x, bytearray)).any():
                # Convert bytearray values to strings
                df[col] = df[col].apply(
                    lambda x: x.decode('utf-8', errors='replace') if isinstance(x, bytearray) else x
                )
        return df
    except Exception as e:
        custom_logger.customLogger().error(f"Failed to convert bytearray columns: {e}")
        raise

def remove_timezone_info(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove timezone information from datetime columns.
    
    Args:
        df (pd.DataFrame): Input DataFrame with potential timezone-aware columns
        
    Returns:
        pd.DataFrame: DataFrame with timezone information removed
    """
    try:
        # Identify columns containing timestamp values
        datetime_columns = [
            col for col in df.columns 
            if any(isinstance(x, pd.Timestamp) for x in df[col].dropna())
        ]
        
        # Process each datetime column
        for col in datetime_columns:
            df[col] = pd.to_datetime(df[col], errors='coerce', utc=True)
            df[col] = df[col].dt.tz_localize(None)
            
        return df
    except Exception as e:
        custom_logger.customLogger().error(f"Failed to remove timezone information: {e}")
        raise

def fill_nulls_and_blanks(df: pd.DataFrame, fill_value: Any = 0) -> pd.DataFrame:
    """
    Fill null values and blank strings in a DataFrame.
    Intelligently handles different column types to prevent type conversion errors.
    
    Args:
        df (pd.DataFrame): Input DataFrame
        fill_value (Any, optional): Value to use for filling. Defaults to 0.
        
    Returns:
        pd.DataFrame: DataFrame with nulls and blanks filled
    """
    try:
        pd.set_option('future.no_silent_downcasting', True)
        # Create a copy to avoid modifying the original
        df_filled = df.copy()
        
        # Process each column separately based on its type
        for col in df_filled.columns:
            col_dtype = df_filled[col].dtype
            
            # For string or object types
            if pd.api.types.is_string_dtype(col_dtype) or col_dtype == 'object':
                # Fill NaN values with string version of fill_value
                df_filled[col] = df_filled[col].fillna(str(fill_value))
                # Replace empty strings with string version of fill_value
                df_filled[col] = df_filled[col].replace('', str(fill_value))
            
            # For numeric types
            elif pd.api.types.is_numeric_dtype(col_dtype):
                # Fill with numeric fill_value
                df_filled[col] = df_filled[col].fillna(fill_value)
            
            # For datetime types
            elif pd.api.types.is_datetime64_dtype(col_dtype):
                # For datetime columns, use NaT for null values
                # Or use a specific date if needed
                df_filled[col] = df_filled[col].fillna(pd.NaT)
            
            # For boolean types
            elif pd.api.types.is_bool_dtype(col_dtype):
                # Use boolean version of fill_value
                bool_fill = bool(fill_value)
                df_filled[col] = df_filled[col].fillna(bool_fill)
            
            # For any other types
            else:
                # Try direct filling, with fallback to string conversion
                try:
                    df_filled[col] = df_filled[col].fillna(fill_value)
                except (TypeError, ValueError):
                    # If type error occurs, convert fill_value to string
                    df_filled[col] = df_filled[col].fillna(str(fill_value))
        
        # Apply infer_objects to ensure proper types
        df_filled = df_filled.infer_objects(copy=False)
        
        return df_filled
    except Exception as e:
        custom_logger.customLogger().error(f"Failed to fill nulls and blanks: {e}")
        raise

def strip_string_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove leading and trailing spaces from string values.
    
    Args:
        df (pd.DataFrame): Input DataFrame
        
    Returns:
        pd.DataFrame: DataFrame with string values stripped
    """
    try:
        # More efficient approach using apply only on string columns
        string_cols = df.select_dtypes(include=['object']).columns
        
        for col in string_cols:
            df[col] = df[col].apply(lambda x: x.strip() if isinstance(x, str) else x)
            
        return df
    except Exception as e:
        custom_logger.customLogger().error(f"Failed to strip string values: {e}")
        raise

def standardize_column_names(df: pd.DataFrame) -> pd.DataFrame:
        """
        Standardize column names for comparison by stripping whitespace,
        replacing underscores with spaces, and converting to uppercase.
        
        Args:
            df: Dataframe to standardize
            
        Returns:
            Dataframe with standardized column names
        """
        try:
            # Strip whitespace and replace underscores with spaces
            df.columns = df.columns.str.strip().str.replace('_', ' ')
            
            # Convert to uppercase
            df.columns = df.columns.str.upper()
            
            return df
            
        except Exception as e:
            custom_logger.customLogger().error(f"Failed: Trim dataframe columns -- {e}")
            raise ValueError(f"Column standardization failed: {e}")



def standardize_dataframes(
    src_df: pd.DataFrame, 
    tgt_df: pd.DataFrame
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Standardize source and target DataFrames for comparison.
    
    Args:
        src_df (pd.DataFrame): Source DataFrame
        tgt_df (pd.DataFrame): Target DataFrame
        db_type (str): Database type ('Snowflake' or other)
        
    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: Standardized source and target DataFrames
    """
    try:
        # Create copies to avoid modifying the originals
        src_df = src_df.copy()
        tgt_df = tgt_df.copy()
        
        # Step 1: Standardize column names
        src_df = standardize_column_names(src_df)
        tgt_df = standardize_column_names(tgt_df)

        # Step 2: Sort columns for consistent comparison
        src_df = src_df.sort_index(axis=1)
        tgt_df = tgt_df.sort_index(axis=1)
        
        # Step 3: Clean and standardize data
        src_df = convert_bytearray_columns(src_df)
        tgt_df = convert_bytearray_columns(tgt_df)
        
        src_df = remove_timezone_info(src_df)
        tgt_df = remove_timezone_info(tgt_df)
        
        src_df = fill_nulls_and_blanks(src_df)
        tgt_df = fill_nulls_and_blanks(tgt_df)
        
        src_df = strip_string_values(src_df)
        tgt_df = strip_string_values(tgt_df)
        
        # Step 4: Align data types between source and target
        aligned_src_df = align_datatypes(src_df, tgt_df)
        
        return aligned_src_df, tgt_df
    except Exception as e:
        custom_logger.customLogger().error(f"Error in standardizing DataFrames: {e}")
        raise

def align_datatypes(source_df: pd.DataFrame, target_df: pd.DataFrame) -> pd.DataFrame:
    """
    Align datatypes of source DataFrame columns with target DataFrame columns.
    
    Args:
        source_df: The DataFrame whose datatypes need to be changed
        target_df: The DataFrame with the desired datatypes
        
    Returns:
        A copy of source_df with column datatypes matched to target_df where possible
    """
    # Create a copy to avoid modifying the original
    result_df = source_df.copy()
    
    # Get common columns between the two DataFrames
    common_columns = set(source_df.columns).intersection(set(target_df.columns))
    
        
    for column in common_columns:
        src_dtype = source_df[column].dtype
        tgt_dtype = target_df[column].dtype
        
        # Skip if datatypes already match
        if str(src_dtype) == str(tgt_dtype):
            continue
            
        #custom_logger.customLogger().info(f"Converting column '{column}' from {src_dtype} to {tgt_dtype}")
        
        try:
            # Handle special case: nullable integer (pandas Int64) to standard integer (int64)
            if str(tgt_dtype) == 'int64' and str(src_dtype) == 'Int64':
                if not result_df[column].isna().any():
                    result_df[column] = result_df[column].astype('int64')
                else:
                    custom_logger.customLogger().warning(f"Column '{column}' has null values, cannot convert from Int64 to int64")
                continue
                
            # Handle PyArrow string type
            if 'string[pyarrow]' in str(tgt_dtype):
                # First convert to regular string
                result_df[column] = result_df[column].astype(str)
                # Try to import PyArrow for proper handling
                try:
                    import pyarrow as pa
                    arrow_array = pa.array(result_df[column].tolist())
                    result_df[column] = pd.Series(arrow_array)
                except ImportError:
                    custom_logger.customLogger().warning(f"PyArrow not available, using string type for column '{column}'")
                    result_df[column] = result_df[column].astype('string')
                continue
                
            # Handle date types
            if 'datetime' in str(tgt_dtype) or 'date' in str(tgt_dtype):
                result_df[column] = pd.to_datetime(result_df[column], errors='coerce')
                continue
                
            # Handle category type
            if str(tgt_dtype) == 'category':
                result_df[column] = result_df[column].astype('category')
                continue
                
            # Generic approach for other types
            result_df[column] = result_df[column].astype(tgt_dtype)
            
        except Exception as e:
            custom_logger.customLogger().error(f"Failed to convert column '{column}' from {src_dtype} to {tgt_dtype}: {e}")
            # Try a more flexible approach through string conversion
            try:
                # Get basic type name without parameters
                basic_type = str(tgt_dtype).split('[')[0]
                result_df[column] = result_df[column].astype(str).astype(basic_type)
                custom_logger.customLogger().info(f"Used alternative conversion for column '{column}'")
            except Exception as e2:
                custom_logger.customLogger().error(f"Alternative conversion also failed for column '{column}': {e2}")
                # Log column statistics for debugging
                if result_df[column].isna().any():
                    custom_logger.customLogger().info(f"Column '{column}' has {result_df[column].isna().sum()} null values")
    
    return result_df

def validate_dataframes(src_df: pd.DataFrame, tgt_df: pd.DataFrame) -> bool:
    """
    Validate that source and target DataFrames are compatible for comparison.
    
    Args:
        src_df (pd.DataFrame): Source DataFrame
        tgt_df (pd.DataFrame): Target DataFrame
        
    Returns:
        bool: True if compatible, False otherwise
    """
    try:
        # Check 1: Number of columns
        if src_df.shape[1] != tgt_df.shape[1]:
            custom_logger.customLogger().error(
                f"Column count mismatch: Source has {src_df.shape[1]} columns, "
                f"Target has {tgt_df.shape[1]} columns"
                f" Source Columns : {src_df.columns}"
                f"Target Columns : {tgt_df.columns}"
            )
            return False
        
        # Check 2: Column names and order
        if not list(src_df.columns) == list(tgt_df.columns):
            custom_logger.customLogger().error("Column names or order mismatch:")
            custom_logger.customLogger().error(f"Source columns: {list(src_df.columns)}")
            custom_logger.customLogger().error(f"Target columns: {list(tgt_df.columns)}")
            return False
        
        # Check 3: Data types
        if not src_df.dtypes.equals(tgt_df.dtypes):
            custom_logger.customLogger().error("Data type mismatch:")
            
            # Create a more readable diff of dtypes
            dtype_diff = pd.DataFrame({
                'Source': src_df.dtypes,
                'Target': tgt_df.dtypes
            }).loc[src_df.dtypes != tgt_df.dtypes]
            
            custom_logger.customLogger().error(f"Data type differences:\n{dtype_diff}")
            return False
        
        return True
    except Exception as e:
        custom_logger.customLogger().error(f"Error validating DataFrames: {e}")
        return False



def compare_dataframes(
    src_df: pd.DataFrame, 
    tgt_df: pd.DataFrame, 
    row: pd.Series, 
    output_file: str
) -> Tuple[pd.DataFrame, Optional[pd.ExcelWriter]]:
    """
    Compare source and target DataFrames and identify differences.
    
    Args:
        src_df (pd.DataFrame): Source DataFrame
        tgt_df (pd.DataFrame): Target DataFrame
        row (pd.Series): Row containing metadata about the comparison
        output_file (str): Path to output Excel file
        
    Returns:
        Tuple[pd.DataFrame, Optional[pd.ExcelWriter]]: 
            - DataFrame containing differences
            - Excel writer object if differences were found
    """
    try:
        # Create copies to avoid modifying the originals
        src_df = src_df.copy()
        tgt_df = tgt_df.copy()
        
        # Add filename columns for tracking
        src_df['Filename'] = row.get('SRC_Data_File', 'Unknown Source')
        tgt_df['Filename'] = row.get('TGT_Data_File', 'Unknown Target')
        
        # Combine DataFrames for comparison
        merged_df = pd.concat([src_df, tgt_df], ignore_index=True)
        
        # Identify rows that are not duplicated (i.e., differences)
        compare_columns = [col for col in src_df.columns if col != 'Filename']
        non_matching_rows = merged_df[~merged_df.duplicated(subset=compare_columns, keep=False)]
        
        # Sort results for better readability
        sort_columns = [col for col in non_matching_rows.columns if col != 'SRC_TGT_File']
        result_df = non_matching_rows.sort_values(by=sort_columns).reset_index(drop=True)
        
        # Write results to Excel if differences were found
        excel_writer = None
        if not result_df.empty:
            custom_logger.customLogger().info(f"Found {len(result_df)} differences between source and target")
            
            # Create Excel writer
            excel_writer = ExcelFileParser.create_excel_writer(output_file)
            
            # Limit to first 1000 rows for practical file sizes
            src_sample = src_df.head(1000)
            tgt_sample = tgt_df.head(1000)
            
            # Write to separate sheets
            src_sample.to_excel(excel_writer, sheet_name='Source data', index=False)
            tgt_sample.to_excel(excel_writer, sheet_name='Target data', index=False)
            result_df.to_excel(excel_writer, sheet_name='Differences', index=False)
            
            custom_logger.customLogger().info(f"Comparison results written to {output_file}")
        else:
            custom_logger.customLogger().info("No differences found between source and target")
            
        return result_df, excel_writer
    except Exception as e:
        custom_logger.customLogger().error(f"Failed to compare DataFrames: {e}")
        raise
