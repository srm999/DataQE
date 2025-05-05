# integration/dataqa_bridge.py
import os
import json
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List, Optional
from flask import current_app
from refactored.data_validation_framework import DataValidationFramework
from refactored.data_validation import DBTablesValidation
from core.file_parsing import ExcelFileParser
import traceback
import shutil

class DataQEBridge:
    """Bridge between DataQE Suite and existing data validation framework"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app

    # Update your DataQEBridge to properly handle binary files:
    def _copy_file_to_project(self, source_file, project_path, new_filename):
        """Copy a file to the project directory"""
                
        target_path = os.path.join(project_path, new_filename)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        # Binary copy
        shutil.copy2(source_file, target_path)
        return target_path

    def prepare_test_case_for_validation(self, test_case, project) -> Dict[str, Any]:
        """Convert DataQE test case to format expected by validation framework"""
        
        # Get project paths
        input_folder = os.path.join(project.folder_path, 'input')
        output_folder = os.path.join(project.folder_path, 'output')
        
        # Prepare test case data
        test_data = {
            'Test_ID': test_case.tcid,
            'Test_Name': test_case.tc_name,
            'Table': test_case.table_name,
            'Test_Type': test_case.test_type,
            'Test_YN': test_case.test_yn,
            'SRC_Data_File': test_case.src_data_file,
            'TGT_Data_File': test_case.tgt_data_file,
            'SRC_Connection': test_case.src_connection.name if test_case.src_connection else None,
            'TGT_Connection': test_case.tgt_connection.name if test_case.tgt_connection else None,
            'Filters': test_case.filters,
            'Delimiter': test_case.delimiter,
            'pk_columns': test_case.pk_columns,
            'Date_Fields': test_case.date_fields,
            'Percentage_Fields': test_case.percentage_fields,
            'Threshold_Percentage': test_case.threshold_percentage,
            'src_sheet_name': test_case.src_sheet_name,
            'tgt_sheet_name': test_case.tgt_sheet_name,
            'header_columns': test_case.header_columns,
            'skip_rows': test_case.skip_rows
        }
        
        return test_data
    
    def prepare_connections_for_validation(self, project) -> pd.DataFrame:
        """Prepare connections data for validation framework"""
        
        connections_data = []
        for conn in project.connections:
            conn_data = {
                'Project': conn.name,
                'Server': conn.server,
                'Database': conn.database,
                'Warehouse': conn.warehouse,
                'Role': conn.role
            }
            connections_data.append(conn_data)
        
        return pd.DataFrame(connections_data)
    
    def execute_test_case(self, test_case, execution_record):
        """Execute a single test case using the validation framework"""
        
        try:
            project = test_case.team.project
            
            # Prepare test configuration
            test_config = self.prepare_test_case_for_validation(test_case, project)
            connections_df = self.prepare_connections_for_validation(project)

            # Check if source or target is an Excel file
            if test_case.src_connection and test_case.src_connection.is_excel:
                # Handle Excel source
                src_path = os.path.join(project.folder_path, 'input', test_case.src_data_file)
                # Make sure the filepath is tracked in test_config
                test_config['SRC_Data_File'] = src_path
            
            if test_case.tgt_connection and test_case.tgt_connection.is_excel:
                # Handle Excel target
                tgt_path = os.path.join(project.folder_path, 'input', test_case.tgt_data_file)
                # Make sure the filepath is tracked in test_config
                test_config['TGT_Data_File'] = tgt_path
            
            # Create temporary config files
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            temp_config_dir = os.path.join(project.folder_path, 'temp_configs')
            os.makedirs(temp_config_dir, exist_ok=True)
            
            # Create Excel config file for validation framework
            config_file = os.path.join(temp_config_dir, f'config_{test_case.tcid}_{timestamp}.xlsx')
            with pd.ExcelWriter(config_file) as writer:
                # Write test case data
                test_df = pd.DataFrame([test_config])
                test_df.to_excel(writer, sheet_name='SRC_TGT_SQL_Pairs', index=False)
                
                # Write connections data
                connections_df.to_excel(writer, sheet_name='Connections', index=False)
            
            # Initialize validation framework
            base_filepath = os.path.join(project.folder_path, 'input', '')
            validation_framework = DataValidationFramework(config_file, base_filepath)
            
            # Execute validation
            start_time = datetime.now()
            
            # Get source and target data
            src_df = validation_framework.retriever.get_data(test_config, is_source=True)
            tgt_df = validation_framework.retriever.get_data(test_config, is_source=False)
            
            if src_df is None or tgt_df is None:
                raise Exception("Failed to retrieve source or target data")
            
            # Apply transformations
            src_df, tgt_df = validation_framework._apply_transformations(src_df, tgt_df, test_config)
            
            # Execute based on test type
            if test_case.test_type == 'Completeness':
                result = self._execute_completeness_test(validation_framework, src_df, tgt_df, test_config)
            elif test_case.test_type == 'Correctness':
                result = self._execute_correctness_test(validation_framework, src_df, tgt_df, test_config, project)
            elif test_case.test_type == 'Duplicate':
                result = self._execute_duplicate_test(validation_framework, src_df, test_config, project)
            else:
                raise Exception(f"Unknown test type: {test_case.test_type}")
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Update execution record
            execution_record.end_time = end_time
            execution_record.duration = duration
            execution_record.status = result['status']
            execution_record.records_compared = result.get('records_compared', 0)
            execution_record.mismatches_found = result.get('mismatches_found', 0)
            execution_record.log_file = result.get('log_file')
            
            if result['status'] == 'FAILED':
                execution_record.error_message = result.get('error_message')
            
            # Clean up temp config file
            if os.path.exists(config_file):
                os.remove(config_file)
            
            return result
            
        except Exception as e:
            error_msg = f"Error executing test case: {str(e)}"
            print(f"Error details:\n{traceback.format_exc()}")
            return {
                'status': 'ERROR',
                'error_message': error_msg,
                'records_compared': 0,
                'mismatches_found': 0
            }
    
    def _execute_completeness_test(self, validation_framework, src_df, tgt_df, test_config):
        """Execute completeness test"""
        
        src_count = len(src_df)
        tgt_count = len(tgt_df)
        
        status, message = validation_framework.comparator.check_threshold(
            src_count, tgt_count, test_config.get('Threshold_Percentage', 0)
        )
        
        return {
            'status': 'PASSED' if status else 'FAILED',
            'records_compared': max(src_count, tgt_count),
            'mismatches_found': abs(src_count - tgt_count) if not status else 0,
            'error_message': message if not status else None,
            'source_count': src_count,
            'target_count': tgt_count
        }
    
    def _execute_correctness_test(self, validation_framework, src_df, tgt_df, test_config, project):
        """Execute correctness test"""
        
        # Get key columns
        pk_columns = json.loads(test_config.get('pk_columns', '[]')) if test_config.get('pk_columns') else []
        
        # Compare dataframes
        compare_result, summary_df = validation_framework.comparator.compare_dataframes(
            src_df, tgt_df, key_columns=pk_columns
        )
        
        # Process results
        if not compare_result.empty:
            # Generate output file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_folder = os.path.join(project.folder_path, 'output')
            mismatch_file = os.path.join(output_folder, f"{test_config['Test_ID']}_mismatches_{timestamp}.xlsx")
            
            # Analyze and categorize mismatches
            validation_framework.diff.analyze_and_categorize_mismatches(
                compare_result,
                key_columns=pk_columns,
                output_file=mismatch_file,
                cmp_summary_df=summary_df
            )
            
            mismatches_found = len(compare_result)
            status = 'FAILED'
        else:
            mismatch_file = None
            mismatches_found = 0
            status = 'PASSED'
        
        return {
            'status': status,
            'records_compared': len(src_df) + len(tgt_df),
            'mismatches_found': mismatches_found,
            'log_file': mismatch_file,
            'summary': summary_df.to_dict() if summary_df is not None else None
        }
    
    def _execute_duplicate_test(self, validation_framework, df, test_config, project):
        """Execute duplicate test"""
        
        # Get key columns
        pk_columns = json.loads(test_config.get('pk_columns', '[]')) if test_config.get('pk_columns') else []
        
        # Check for duplicates
        duplicate_records = validation_framework.comparator.check_duplicates(df, key_columns=pk_columns)
        
        if not duplicate_records.empty:
            # Generate output file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_folder = os.path.join(project.folder_path, 'output')
            duplicate_file = os.path.join(output_folder, f"{test_config['Test_ID']}_duplicates_{timestamp}.xlsx")
            
            with pd.ExcelWriter(duplicate_file) as writer:
                duplicate_records.to_excel(writer, sheet_name='Duplicates', index=False)
            
            status = 'FAILED'
            mismatches_found = len(duplicate_records)
            log_file = duplicate_file
        else:
            status = 'PASSED'
            mismatches_found = 0
            log_file = None
        
        return {
            'status': status,
            'records_compared': len(df),
            'mismatches_found': mismatches_found,
            'log_file': log_file
        }