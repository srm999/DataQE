from typing import Dict, List, Tuple, Optional, Any
import allure
import pandas as pd
import numpy as np
from pathlib import Path
from core.file_parsing import ExcelFileParser
from core.data_diffs import DataComparator, DataDiff
from utils import custom_logger
from refactored.data_validation_framework import DataRetriever, DataValidationFramework
from core.data_processing import *

class DBTablesValidation:
    """
    Database Tables validation tests
    """
    def __init__(self, config_file: str, base_filepath: str):
        self.config_file = config_file
        self.base_filepath = base_filepath
        self.log = custom_logger.customLogger()
        self.current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Read configuration from Excel
        self.DVFramework = DataValidationFramework(self.config_file,self.base_filepath)
        self.src_tgt_data_info, self.db_info = self.DVFramework._read_configuration()
        
        # Initialize components
        self.retriever = DataRetriever(self.db_info, self.base_filepath)
        self.comparator = DataComparator()
        self.diff = DataDiff()

   
    
    def _export_mismatch_data(self, df: pd.DataFrame, filename: str, sheetname: str = 'Mismatch Records') -> str:
        """Helper method to export DataFrame to Excel file"""
        try:
            excel_writer = ExcelFileParser.create_excel_writer(filename)
            ExcelFileParser.write_to_excel(df, excel_writer, sheet_name=sheetname)
            ExcelFileParser.save_excel_writer(excel_writer)
            return filename
        except Exception as e:
            self.log.error(f"Failed to export data to {filename}: {e}")
            return ""
    
    def _generate_mismatch_filepath(self, base_path: str, table_name: str, test_type: str) -> str:
        """Generate a consistent filepath for mismatch data"""
        return f"{base_path}DB_{table_name}_{test_type}_{self.current_time}.xlsx"
    
    def _perform_completeness_check(
            self, 
            row: pd.Series, 
            src_df: pd.DataFrame,
            tgt_df: pd.DataFrame, ) -> Tuple[bool]:
        """Perform completeness check and return result and dataframes"""        
        try:
            self.log.info(" Performing Completeness Validation :")
            if src_df is None:
                self.log.error(f"Failed: reading source file for {row['Table']} Table CC validation")
                return False, None, None
            src_count = len(src_df.index)
        
            if tgt_df is None:
                self.log.error(f"Failed: reading target file for {row['Table']} Table CC validation")
                return False, None, None
            tgt_count = len(tgt_df.index)
            
            # Check if counts are within threshold
            status, message = self.comparator.check_threshold(
                src_count, tgt_count, row['Threshold_Percentage']
            )
            
            result_message = (
                f"{row['Table']} Completeness Source count is: {src_count}\n"
                f"{row['Table']} Completeness Target Count is: {tgt_count}\n"
                f"{row['Table']} Completeness validation {'Passed' if status else 'Failed'}: {message}"
            )
            
            self.log.info(f"{result_message}")
            allure.attach(result_message, name = "Source and Target counts",attachment_type=allure.attachment_type.TEXT)
            return status
        except Exception as e:
            self.log.error(f"Failed: Completeness validation - {e}")
            return False
    
    def _perform_correctness_check(
        self, 
        src_df: pd.DataFrame, 
        tgt_df: pd.DataFrame, 
        row: pd.Series, 
        mismatch_path: str,
        key_columns=None
    ) -> Tuple[bool, List[str]]:
        """Perform correctness check and return result and list of mismatch files"""
        try:
            
                self.log.info(" Performing Correctness Validation :")
                mismatch_files = []
                params = self.retriever.get_config_params(row, True)
                key_columns = params['pk_columns'] 
                
                # Apply project specific transformations

                src_df, tgt_df = self.DVFramework._apply_transformations(src_df, tgt_df, row)
                
                
                # Compare dataframes
                mismatch_file = self._generate_mismatch_filepath(mismatch_path, row['Table'], "Correctness_mismatch_data")
                compare_src_tgt_df,compare_src_tgt_df_summ = self.comparator.compare_dataframes(src_df, tgt_df,key_columns = key_columns)
                #compare_src_tgt_df,compare_src_tgt_df_summ = dctemp.compare_large_dataframes(src_df, tgt_df,key_columns)
                
                                
                if compare_src_tgt_df.shape[0] == 0:
                    self.log.info(f"{row['Table']} Table - Correctness check validated successfully {compare_src_tgt_df_summ}")
                    return True, mismatch_files
                else:
                    mismatch_files.append(mismatch_file)
                    self.diff.analyze_and_categorize_mismatches(compare_src_tgt_df,key_columns=key_columns,output_file=mismatch_file,cmp_summary_df=compare_src_tgt_df_summ)
                    failure_msg = f"{row['Table']} - table Correctness check Failed, Mismatched records exported to file: {mismatch_file}"
                    self.log.info(f" {compare_src_tgt_df_summ}")
                    allure.attach(failure_msg, name = 'Mismatch Records', attachment_type=allure.attachment_type.TEXT)
                    return False, mismatch_files 
                    
        except Exception as e:
            self.log.error(f"Failed: Correctness validation - {e}")
            return False, []
    
    def _perform_duplicate_check(self, df: pd.DataFrame, row: pd.Series, mismatch_path: str) -> Tuple[bool, List[str]]:
        """Perform duplicate check and return result and list of duplicate files"""
        try:
            self.log.info(" Performing Duplicate check :")
            file_list = []
            params = self.retriever.get_config_params(row, True)
            key_columns = params['pk_columns'] 

            # Check for duplicates
            duplicate_records = self.comparator.check_duplicates(df,key_columns = key_columns)
            
            if len(duplicate_records.index) == 0:
                self.log.info(f"{row['Table']} table Duplicate Check passed successfully, No Duplicate records found")
                return True, file_list
            else:
                duplicate_file = self._generate_mismatch_filepath(mismatch_path, row['Table'], "Table_Duplicates")
                file_list.append(duplicate_file)
                
                # Export duplicate records
                excel_writer = ExcelFileParser.create_excel_writer(duplicate_file)
                ExcelFileParser.write_to_excel(duplicate_records, excel_writer, sheetName='Duplicates')
                ExcelFileParser.save_excel_writer(excel_writer)
                
                failure_msg = f"{row['Table']} - table Duplicate records exported to file: {duplicate_file}"
                self.log.error(failure_msg)
                allure.attach(
                    f"{row['Table']} - table Duplicate Check Failed, Duplicate records exported to file: {duplicate_file}", 
                    name = 'Duplicate Records',
                    attachment_type=allure.attachment_type.TEXT
                )
                return False, file_list
        except Exception as e:
            self.log.error(f"Failed: Duplicate check - {e}")
            return False, []
    
    def _perform_constraint_check(self, row: pd.Series, db_info: Dict, db_filepath: str, mismatch_path: str) -> bool:
        """Perform constraint check and return result"""
        try:
            # Get constraint check data
            constraint_results = DataRetriever.get_data(row, False)
            if constraint_results is None:
                self.log.error(f"Failed: reading target file for {row['Table']} Table for Constraint Check")
                return False
            
            constraint_count = len(constraint_results.index)
            
            if constraint_count == 0:
                self.log.info(f"{row['Table']} table Constraint Check passed successfully, No Constraint Check Violated records found")
                return True
            else:
                # Export constraint violation records
                constraint_file = self._generate_mismatch_filepath(mismatch_path, row['Table'], "Table_ConstraintCheck")
                excel_writer = ExcelFileParser.create_excel_writer(constraint_file)
                ExcelFileParser.write_to_excel(constraint_results, excel_writer, sheetName='ConstraintCheck')
                ExcelFileParser.save_excel_writer(excel_writer)
                
                failure_msg = f"{row['Table']} - table Constraint Check Failed, Violated records exported to file: {constraint_file}"
                self.log.error(failure_msg)
                allure.attach(failure_msg, name = 'Constraint Check Failed Records', attachment_type=allure.attachment_type.TEXT)
                return False
        except Exception as e:
            self.log.error(f"Failed: Constraint check - {e}")
            return False
        
    def detect_value_mismatches(self,df, key_columns, source_column='__source'):
        """
        A simplified function focused solely on detecting value mismatches between source and target rows.
        
        Parameters:
        -----------
        df : pd.DataFrame
            The dataframe containing both source and target rows
        key_columns : list
            List of column names that uniquely identify records
        source_column : str, default='__source'
            Column name that identifies rows as 'Source' or 'Target'
            
        Returns:
        --------
        dict
            Dictionary of mismatches: {key: [(column, source_value, target_value), ...]}
        """
        import pandas as pd
        
        # Confirm key columns and source column exist
        for col in key_columns + [source_column]:
            if col not in df.columns:
                print(f"Column {col} not found in dataframe")
                return {}
        
        # Separate source and target rows
        source_df = df[df[source_column] == 'Source'].copy()
        target_df = df[df[source_column] == 'Target'].copy()
        
        print(f"Found {len(source_df)} source rows and {len(target_df)} target rows")
        
        # Get all value columns (non-key, non-source columns)
        value_columns = [col for col in df.columns if col not in key_columns and col != source_column]
        print(f"Value columns to compare: {value_columns}")
        
        # Create join keys for source and target
        source_df['_join_key'] = source_df.apply(lambda row: '-'.join([str(row[col]) for col in key_columns]), axis=1)
        target_df['_join_key'] = target_df.apply(lambda row: '-'.join([str(row[col]) for col in key_columns]), axis=1)
        
        # Print join keys for debugging
        print("Sample source join keys:", source_df['_join_key'].head().tolist())
        print("Sample target join keys:", target_df['_join_key'].head().tolist())
        
        # Get common keys
        source_keys = set(source_df['_join_key'])
        target_keys = set(target_df['_join_key'])
        common_keys = source_keys.intersection(target_keys)
        
        print(f"Found {len(common_keys)} common keys")
        
        # Create lookup dictionaries for faster access
        source_lookup = {row['_join_key']: row for _, row in source_df.iterrows()}
        target_lookup = {row['_join_key']: row for _, row in target_df.iterrows()}
        
        # Find mismatches for each common key
        mismatches = {}
        for key in common_keys:
            source_row = source_lookup[key]
            target_row = target_lookup[key]
            
            # Check each value column for differences
            column_mismatches = []
            for col in value_columns:
                source_val = source_row[col]
                target_val = target_row[col]
                
                # Handle NaN values
                if pd.isna(source_val) and pd.isna(target_val):
                    continue
                elif pd.isna(source_val) or pd.isna(target_val):
                    column_mismatches.append((col, source_val, target_val))
                    print(f"NaN mismatch found in {col} for key {key}")
                # Compare values
                elif source_val != target_val:
                    column_mismatches.append((col, source_val, target_val))
                    print(f"Value mismatch found in {col} for key {key}: {source_val} vs {target_val}")
            
            # If mismatches were found, add to results
            if column_mismatches:
                mismatches[key] = column_mismatches
        
        print(f"Found {len(mismatches)} keys with value mismatches")
        # Print details of mismatches
        for key, details in mismatches.items():
            print(f"Key: {key}")
            for col, src_val, tgt_val in details:
                print(f"  Column {col}: {src_val} vs {tgt_val}")
        
        return mismatches
            
        