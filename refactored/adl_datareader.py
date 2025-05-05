import logging
import tempfile
import pyodbc
import os
import re
import ast
import uuid
import shutil
from urllib.parse import urlparse
from datetime import datetime

# Required imports - moved to top level to avoid reference errors
import pandas as pd
from azure.storage.blob import BlobServiceClient
import deltalake
import yaml

class MyAzureReader:
    
    def __init__(self, config_path='config.yml'):
        """
        Initialize the Azure reader with configuration.
        
        Args:
            config_path (str): Path to the YAML configuration file.
        """
        from utils.custom_logger import customLogger
        self.log = customLogger()
        
        # Load configuration
        try:
            with open(config_path) as c:
                config = yaml.safe_load(c)
            self.account_name = config['DEFAULT']['ACCOUNT_NAME']
            self.account_key = config['DEFAULT']['ACCOUNT_KEY']
        except Exception as e:
            self.log.error(f"Error loading configuration: {str(e)}")
            raise
            
        # Set higher log levels for Azure libraries
        azure_logger = "azure.core.pipeline.policies.http_logging_policy"
        logging.getLogger(azure_logger).setLevel(logging.WARNING)
        logging.getLogger('azure').setLevel(logging.WARNING)
        logging.getLogger('azure.core').setLevel(logging.WARNING)
        logging.getLogger('azure.storage').setLevel(logging.WARNING)

    def read_blob_from_azure(self, row, azure_path, file_format='parquet', delta_version=None, filters=None):
        """
        Read data from Azure Blob Storage.
        
        Args:
            row: Row identifier (used for logging)
            azure_path (str): Path to the blob in Azure
            file_format (str): Format of the data ('parquet' or 'delta')
            delta_version (int, optional): Version of the delta table to read
            filters (dict or str, optional): Filters to apply to the data
            
        Returns:
            pandas.DataFrame: The loaded data
        """
        # Initialize variables
        container_name = None
        blob_path = None
        df = None
        temp_base_dir = None
        
        try:
            start = datetime.now()
            
            # Process filters if it's a string
            if filters and isinstance(filters, str):
                self.log.info(f"Processing string filter: {filters}")
                try:
                    # Try to parse the string as a literal Python dictionary
                    filters = ast.literal_eval(filters)
                except (SyntaxError, ValueError) as e:
                    # More robust parsing with simple regex
                    if re.match(r"^\s*{\s*['\"](.*?)['\"]\s*:\s*\(\s*['\"](.*?)['\"]\s*,\s*['\"](.*?)['\"].*?\)\s*}\s*$", filters):
                        match = re.match(r"^\s*{\s*['\"](.*?)['\"]\s*:\s*\(\s*['\"](.*?)['\"]\s*,\s*['\"](.*?)['\"].*?\)\s*}\s*$", filters)
                        if match:
                            col_name, operator, value = match.groups()
                            filters = {col_name: (operator, value)}
                    else:
                        self.log.warning(f"Could not parse filter string: {filters}")
                        filters = None
            
            # Parse the Azure path
            if azure_path.startswith('http'):
                parsed_url = urlparse(azure_path)
                path_parts = parsed_url.path.strip('/').split('/', 1)
                if len(path_parts) < 2:
                    raise ValueError(f"Invalid path in URL: {azure_path}. Must contain container and blob path.")
                container_name, blob_path = path_parts
            else:
                path_parts = azure_path.strip('/').split('/', 1)
                if len(path_parts) < 2:
                    raise ValueError(f"Invalid path format. Expected 'container/blob_path': {azure_path}")
                container_name, blob_path = path_parts
            
            # Connect to Azure Blob Storage
            connection_string = f"DefaultEndpointsProtocol=https;AccountName={self.account_name};AccountKey={self.account_key};EndpointSuffix=core.windows.net"
            blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            container_client = blob_service_client.get_container_client(container_name)
            
            # Check if container exists
            try:
                container_client.get_container_properties()
            except Exception as e:
                raise ValueError(f"Container '{container_name}' does not exist or cannot be accessed: {str(e)}")
            
            # Handle Parquet files
            if file_format.lower() == 'parquet':
                df = self._read_parquet(container_client, blob_path, filters)
            
            # Handle Delta tables
            elif file_format.lower() == 'delta':
                df = self._read_delta(container_client, blob_path, delta_version, filters)
            
            else:
                raise ValueError(f"Unsupported file format: {file_format}. Use 'parquet' or 'delta'.")
            
            # Return DataFrame
            end = datetime.now()
            if df is None:
                raise ValueError("No data was loaded. Check file_format parameter and ensure data exists.")
                
            self.log.info(f"{len(df.index)} records {file_format} file load time -- {end-start}")
            return df
            
        except Exception as e:
            self.log.error(f"Error reading data from Azure: {str(e)}")
            raise
        finally:
            # Clean up temporary directory if it exists
            if temp_base_dir and os.path.exists(temp_base_dir):
                try:
                    shutil.rmtree(temp_base_dir, ignore_errors=True)
                except Exception as cleanup_e:
                    self.log.warning(f"Failed to clean up temporary directory: {str(cleanup_e)}")
    
    def _read_parquet(self, container_client, blob_path, filters=None):
        """
        Read Parquet data from Azure Blob Storage.
        
        Args:
            container_client: Azure container client
            blob_path (str): Path to the blob
            filters (dict, optional): Filters to apply to the data
            
        Returns:
            pandas.DataFrame: The loaded data
        """
        # Try to use Dask for memory-efficient processing
        try:
            import dask.dataframe as dd
            self.log.info("Using Dask for Parquet processing")
            
            # Create a temporary file for single file approach
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.parquet')
            temp_path = temp_file.name
            temp_file.close()
            
            # Try to download as a single file first
            single_file_found = False
            try:
                # Check if blob_path is a single file
                blob_client = container_client.get_blob_client(blob_path)
                blob_client.get_blob_properties()  # Will raise error if not found
                
                # Download file
                with open(temp_path, 'wb') as f:
                    download_stream = blob_client.download_blob()
                    for chunk in download_stream.chunks():
                        f.write(chunk)
                
                single_file_found = True
                
            except Exception:
                # Try with .parquet extension
                if not blob_path.endswith('.parquet'):
                    try:
                        alt_path = f"{blob_path}.parquet"
                        blob_client = container_client.get_blob_client(alt_path)
                        blob_client.get_blob_properties()
                        
                        with open(temp_path, 'wb') as f:
                            download_stream = blob_client.download_blob()
                            for chunk in download_stream.chunks():
                                f.write(chunk)
                        
                        single_file_found = True
                    except Exception:
                        pass
            
            # Process the file or directory
            if single_file_found:
                # Prepare Dask filters
                dask_filters = self._prepare_dask_filters(filters)
                
                # Read the file
                try:
                    if dask_filters:
                        ddf = dd.read_parquet(temp_path, filters=dask_filters)
                    else:
                        ddf = dd.read_parquet(temp_path)
                    
                    # Convert to pandas
                    df = ddf.compute()
                    
                finally:
                    # Clean up
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                
            else:
                # Handle directory of parquet files
                blobs = list(container_client.list_blobs(name_starts_with=blob_path))
                parquet_blobs = [b for b in blobs if b.name.endswith('.parquet')]
                
                if not parquet_blobs:
                    raise ValueError(f"No Parquet files found in path {blob_path}")
                
                # Create a directory for the files
                temp_dir = tempfile.mkdtemp(prefix='azure_parquet_')
                
                try:
                    # Download all files
                    for i, blob in enumerate(parquet_blobs):
                        local_path = os.path.join(temp_dir, f"part_{i:05d}.parquet")
                        blob_client = container_client.get_blob_client(blob.name)
                        
                        with open(local_path, 'wb') as f:
                            download_stream = blob_client.download_blob()
                            f.write(download_stream.readall())
                    
                    # Prepare filters
                    dask_filters = self._prepare_dask_filters(filters)
                    
                    # Read the directory
                    if dask_filters:
                        ddf = dd.read_parquet(os.path.join(temp_dir, "*.parquet"), filters=dask_filters)
                    else:
                        ddf = dd.read_parquet(os.path.join(temp_dir, "*.parquet"))
                    
                    # Convert to pandas
                    df = ddf.compute()
                    
                finally:
                    # Clean up
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir, ignore_errors=True)
            
        except ImportError:
            # Fall back to pandas for smaller files
            self.log.warning("Dask not available. Using pandas directly.")
            df = self._read_parquet_with_pandas(container_client, blob_path)
        
        # Apply filters after loading
        if df is not None and filters and isinstance(filters, dict):
            df = self._apply_filters(df, filters)
        
        return df
    
    def _read_parquet_with_pandas(self, container_client, blob_path):
        """
        Read Parquet data using pandas when Dask is not available.
        
        Args:
            container_client: Azure container client
            blob_path (str): Path to the blob
            
        Returns:
            pandas.DataFrame: The loaded data
        """
        # Try as single file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.parquet')
        temp_path = temp_file.name
        temp_file.close()
        
        try:
            blob_client = container_client.get_blob_client(blob_path)
            blob_client.get_blob_properties()
            
            with open(temp_path, 'wb') as f:
                download_stream = blob_client.download_blob()
                f.write(download_stream.readall())
            
            df = pd.read_parquet(temp_path)
            return df
            
        except Exception:
            # Try with extension
            if not blob_path.endswith('.parquet'):
                try:
                    alt_path = f"{blob_path}.parquet"
                    blob_client = container_client.get_blob_client(alt_path)
                    
                    with open(temp_path, 'wb') as f:
                        download_stream = blob_client.download_blob()
                        f.write(download_stream.readall())
                    
                    df = pd.read_parquet(temp_path)
                    return df
                    
                except Exception:
                    # Try as directory
                    blobs = list(container_client.list_blobs(name_starts_with=blob_path))
                    parquet_blobs = [b for b in blobs if b.name.endswith('.parquet')]
                    
                    if not parquet_blobs:
                        raise ValueError(f"No Parquet files found in path {blob_path}")
                    
                    # Process multiple files
                    dfs = []
                    for blob in parquet_blobs:
                        part_file = tempfile.NamedTemporaryFile(delete=False, suffix='.parquet')
                        part_path = part_file.name
                        part_file.close()
                        
                        try:
                            blob_client = container_client.get_blob_client(blob.name)
                            with open(part_path, 'wb') as f:
                                download_stream = blob_client.download_blob()
                                f.write(download_stream.readall())
                            
                            # Read with pandas
                            temp_df = pd.read_parquet(part_path)
                            dfs.append(temp_df)
                        finally:
                            if os.path.exists(part_path):
                                os.unlink(part_path)
                    
                    # Combine all dataframes
                    if dfs:
                        return pd.concat(dfs, ignore_index=True)
                    else:
                        raise ValueError("No data found in any of the parquet files")
            else:
                raise ValueError(f"Failed to read parquet file at {blob_path}")
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def _read_delta(self, container_client, blob_path, delta_version=None, filters=None):
        """
        Read Delta table from Azure Blob Storage.
        
        Args:
            container_client: Azure container client
            blob_path (str): Path to the blob
            delta_version (int, optional): Version of the delta table to read
            filters (dict, optional): Filters to apply to the data
            
        Returns:
            pandas.DataFrame: The loaded data
        """
        # Create a unique temporary directory in a location with guaranteed access
        # Try to use a more accessible path than the default temp directory
        try:
            # Try current directory first - often has better permissions
            base_temp = os.path.join(os.getcwd(), "temp_delta")
            
            # Create the base temp directory if it doesn't exist
            if not os.path.exists(base_temp):
                os.makedirs(base_temp, exist_ok=True)
                
            # Now create our specific temp directory
            unique_id = str(uuid.uuid4())
            temp_base_dir = os.path.join(base_temp, f"delta_read_{unique_id}")
            os.makedirs(temp_base_dir, exist_ok=True)
            
            self.log.info(f"Created temporary directory in current working directory: {temp_base_dir}")
        except Exception as e:
            # Fall back to system temp directory
            self.log.warning(f"Failed to create temp directory in current directory: {str(e)}")
            unique_id = str(uuid.uuid4())
            temp_base_dir = os.path.join(tempfile.gettempdir(), f"delta_read_{unique_id}")
            os.makedirs(temp_base_dir, exist_ok=True)
            self.log.info(f"Using system temp directory instead: {temp_base_dir}")
        
        try:
            # Check for _delta_log folder
            log_path = f"{blob_path}/_delta_log"
            log_files = list(container_client.list_blobs(name_starts_with=log_path))
            
            if not log_files:
                # Try alternate path format
                if blob_path.endswith('/'):
                    alt_log_path = f"{blob_path[:-1]}/_delta_log"
                else:
                    alt_log_path = f"{blob_path}_delta_log"
                log_files = list(container_client.list_blobs(name_starts_with=alt_log_path))
                if log_files:
                    log_path = alt_log_path
            
            if not log_files:
                raise ValueError(f"No Delta table log files found at {blob_path}")
            
            # Create subdirectories
            metadata_dir = os.path.join(temp_base_dir, "_delta_log")
            data_dir = os.path.join(temp_base_dir, "data")
            os.makedirs(metadata_dir, exist_ok=True)
            os.makedirs(data_dir, exist_ok=True)
            
            # Download only _delta_log/000*.json files and latest version
            json_log_files = [f for f in log_files if f.name.endswith('.json')]
            
            # Sort log files by version number for selective download
            numbered_logs = []
            for blob in json_log_files:
                file_name = os.path.basename(blob.name)
                try:
                    version_num = int(file_name.split('.')[0])
                    numbered_logs.append((version_num, blob))
                except (ValueError, IndexError):
                    # Not a version file, just include it
                    numbered_logs.append((-1, blob))
            
            # Sort by version
            numbered_logs.sort(key=lambda x: x[0])
            
            # OPTIMIZATION: Only download the latest version or requested version and metadata
            if delta_version is not None:
                # Find files for the requested version
                required_logs = [blob for ver, blob in numbered_logs if ver <= delta_version or ver == -1]
                if not any(ver == delta_version for ver, _ in numbered_logs):
                    self.log.warning(f"Delta version {delta_version} not found in log files")
            else:
                # Get the latest version and all prior versions
                if numbered_logs:
                    latest_version = max(ver for ver, _ in numbered_logs if ver != -1)
                    required_logs = [blob for ver, blob in numbered_logs if ver <= latest_version or ver == -1]
                else:
                    required_logs = [blob for _, blob in numbered_logs]
            
            # Download required log files
            for blob in required_logs:
                file_name = os.path.basename(blob.name)
                local_path = os.path.join(metadata_dir, file_name)
                
                blob_client = container_client.get_blob_client(blob.name)
                with open(local_path, "wb") as file:
                    download_data = blob_client.download_blob()
                    file.write(download_data.readall())
            
            # Import required modules here to avoid scope issues
            import json
            import concurrent.futures
            
            # Parse the log files to identify only needed parquet files
            parquet_files_to_download = set()
            
            # First check the latest checkpoint if available (faster than parsing all logs)
            checkpoint_files = [f for f in os.listdir(metadata_dir) if f.endswith('.checkpoint.parquet')]
            if checkpoint_files:
                # Use the latest checkpoint instead of parsing all logs
                checkpoint_files.sort(reverse=True)
                latest_checkpoint = os.path.join(metadata_dir, checkpoint_files[0])
                
                try:
                    import pyarrow.parquet as pq
                    table = pq.read_table(latest_checkpoint)
                    df_checkpoint = table.to_pandas()
                    
                    # Get all active files from the checkpoint
                    if 'path' in df_checkpoint.columns:
                        for path in df_checkpoint['path']:
                            if isinstance(path, str) and path.endswith('.parquet'):
                                parquet_files_to_download.add(path)
                except Exception as e:
                    self.log.warning(f"Error reading checkpoint file: {str(e)}")
                    # Fall back to log parsing
                    checkpoint_files = []
            
            # If no checkpoint or checkpoint processing failed, parse logs
            if not checkpoint_files:
                for log_file in sorted(os.listdir(metadata_dir)):
                    if log_file.endswith('.json'):
                        log_path = os.path.join(metadata_dir, log_file)
                        log_content = self._read_log_with_fallback(log_path)
                        if log_content:
                            # Process the log content line by line
                            for line in log_content.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                    
                                try:
                                    entry = json.loads(line)
                                    # Check for add actions
                                    if 'add' in entry:
                                        parquet_files_to_download.add(entry['add']['path'])
                                    # Check for remove actions to exclude
                                    if 'remove' in entry:
                                        parquet_files_to_download.discard(entry['remove']['path'])
                                except json.JSONDecodeError as json_err:
                                    self.log.warning(f"JSON decode error in {log_file}: {str(json_err)}")
                                    continue
            
            # Prepare base path for parquet files
            data_files_path = blob_path
            if data_files_path.endswith('/_delta_log'):
                data_files_path = data_files_path[:-len('/_delta_log')]
            elif data_files_path.endswith('_delta_log'):
                data_files_path = data_files_path[:-len('_delta_log')]
            
            # Log how many files we need to download
            self.log.info(f"Downloading {len(parquet_files_to_download)} parquet files for Delta table")
            
            # Download files in parallel with a reasonable thread limit
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for i, file_path in enumerate(parquet_files_to_download):
                    futures.append(executor.submit(
                        self._download_parquet_file, 
                        container_client, 
                        i, 
                        file_path, 
                        data_files_path,
                        data_dir
                    ))
                
                # Get results
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            self.log.info(f"Successfully downloaded {sum(results)} of {len(parquet_files_to_download)} files")
            
            # Try reading with Dask first (since it's successful), then fallback to Delta API if needed
            try:
                self.log.info("Using Dask as primary method for Delta table reading")
                df = self._read_delta_parquet_files(data_dir, filters)
                
                # If we successfully read with Dask, log it and return the result
                if df is not None and len(df) > 0:
                    self.log.info(f"Successfully read Delta table with Dask: {len(df)} rows")
                    
                    # Apply filters after loading if they weren't applied during reading
                    # Make sure we don't apply filters twice
                    if filters and isinstance(filters, dict) and 'filters_applied_during_read' not in df.attrs:
                        rows_before = len(df)
                        df = self._apply_filters(df, filters)
                        self.log.info(f"Applied post-read filters: from {rows_before} to {len(df)} rows")
                    
                    return df
                    
            except Exception as dask_err:
                self.log.warning(f"Dask reading failed: {str(dask_err)}")
                # Continue to try Delta API
            
            # Only try Delta API as fallback if Dask fails
            try:
                # Convert the path to absolute path with forward slashes for better compatibility
                delta_path = os.path.abspath(temp_base_dir).replace('\\', '/')
                self.log.info(f"Falling back to Delta API. Attempting to read Delta table from: {delta_path}")
                
                # Try to use Delta Lake API
                dt = deltalake.DeltaTable(delta_path, version=delta_version)
                df = dt.to_pandas()
                self.log.info(f"Successfully read Delta table with Delta API: {len(df)} rows")
                return df
                
            except Exception as delta_err:
                self.log.warning(f"Delta API read failed: {str(delta_err)}")
                
                # If both methods failed, raise an error
                if df is None:
                    raise ValueError("Failed to read Delta table with both Dask and Delta API")
            
            # Apply filters after loading
            if df is not None and filters and isinstance(filters, dict):
                df = self._apply_filters(df, filters)
            
            return df
                
        except Exception as e:
            self.log.error(f"Error reading Delta table: {str(e)}")
            raise
        finally:
            # Clean up temporary files
            if os.path.exists(temp_base_dir):
                try:
                    shutil.rmtree(temp_base_dir, ignore_errors=True)
                except Exception as cleanup_e:
                    self.log.warning(f"Failed to clean up temporary directory: {str(cleanup_e)}")
    
    def _read_log_with_fallback(self, log_path):
        """
        Read a log file with fallback to different encodings.
        
        Args:
            log_path (str): Path to the log file
            
        Returns:
            str: The log file content or None if failed
        """
        # Try different encodings
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        for encoding in encodings_to_try:
            try:
                with open(log_path, 'r', encoding=encoding) as f:
                    log_content = f.read()
                self.log.info(f"Successfully read log file with {encoding} encoding")
                return log_content
            except UnicodeDecodeError:
                continue
        
        # If all encodings failed, try reading as binary and decode manually
        try:
            with open(log_path, 'rb') as f:
                binary_content = f.read()
                # Use a more tolerant decoding method that replaces errors
                log_content = binary_content.decode('utf-8', errors='replace')
                self.log.info(f"Decoded log file with error replacement")
                return log_content
        except Exception as e:
            self.log.warning(f"Failed to read log file: {str(e)}")
            return None
    
    def _download_parquet_file(self, container_client, i, file_path, data_files_path, data_dir):
        """
        Download a parquet file from Azure Blob Storage.
        
        Args:
            container_client: Azure container client
            i (int): File index
            file_path (str): Path to the parquet file
            data_files_path (str): Base path for data files
            data_dir (str): Directory to save downloaded files
            
        Returns:
            bool: True if download successful, False otherwise
        """
        if file_path.startswith('/'):
            file_path = file_path[1:]  # Remove leading slash
        
        full_blob_path = f"{data_files_path}/{file_path}"
        local_path = os.path.join(data_dir, f"data_{i:05d}.parquet")
        
        try:
            blob_client = container_client.get_blob_client(full_blob_path)
            with open(local_path, "wb") as file:
                download_data = blob_client.download_blob()
                file.write(download_data.readall())
            return True
        except Exception as e:
            self.log.warning(f"Error downloading parquet file {full_blob_path}: {str(e)}")
            return False
    
    def _read_delta_parquet_files(self, data_dir, filters=None):
        """
        Read Delta parquet files using Dask or pandas.
        
        Args:
            data_dir (str): Directory containing parquet files
            filters (dict, optional): Filters to apply to the data
            
        Returns:
            pandas.DataFrame: The loaded data
        """
        # Try to use Dask for memory-efficient reading of parquet files
        try:
            import dask.dataframe as dd
            self.log.info("Using Dask for parallel and memory-efficient parquet reading")
            
            # Look for parquet files in the directory
            data_files = [os.path.join(data_dir, f) for f in os.listdir(data_dir) 
                        if f.endswith('.parquet')]
            
            if not data_files:
                self.log.warning(f"No parquet files found in {data_dir}")
                return None
                
            self.log.info(f"Found {len(data_files)} parquet files to read")
            
            # Track if filters were applied during reading
            filters_applied = False
            
            # Prepare Dask filters - only use basic filters during read time
            dask_filters = None
            if filters and isinstance(filters, dict):
                dask_filters = self._prepare_dask_filters(filters)
                if dask_filters:
                    filters_applied = True
                    self.log.info(f"Prepared Dask filters: {dask_filters}")
                else:
                    self.log.info("No compatible Dask filters could be prepared")
            
            # Read all parquet files with Dask
            try:
                if dask_filters:
                    self.log.info(f"Reading with filters: {dask_filters}")
                    ddf = dd.read_parquet(os.path.join(data_dir, "*.parquet"), filters=dask_filters)
                else:
                    ddf = dd.read_parquet(os.path.join(data_dir, "*.parquet"))
                
                # Convert to pandas DataFrame with progress reporting
                self.log.info("Computing Dask DataFrame")
                df = ddf.compute()
                
                # Mark if filters were applied during read
                if filters_applied:
                    df.attrs['filters_applied_during_read'] = True
                
                self.log.info(f"Successfully read with Dask: {len(df)} rows")
                return df
            except Exception as e:
                self.log.warning(f"Error while reading with Dask: {str(e)}")
                self.log.info("Trying alternative Dask approach with explicit file list")
                
                # Try an alternative approach with explicit file list
                try:
                    if dask_filters:
                        ddf = dd.read_parquet(data_files, filters=dask_filters)
                    else:
                        ddf = dd.read_parquet(data_files)
                    
                    df = ddf.compute()
                    
                    # Mark if filters were applied during read
                    if filters_applied:
                        df.attrs['filters_applied_during_read'] = True
                        
                    self.log.info(f"Successfully read with Dask (alternative approach): {len(df)} rows")
                    return df
                except Exception as alt_err:
                    self.log.warning(f"Alternative Dask approach failed: {str(alt_err)}")
                    # Fall back to pandas
                    return self._read_delta_parquet_with_pandas(data_dir)
            
        except ImportError:
            # Fall back to pandas read with parallel processing
            self.log.info("Dask not available, using pandas with parallel processing")
            return self._read_delta_parquet_with_pandas(data_dir)
    
    def _read_delta_parquet_with_pandas(self, data_dir):
        """
        Read Delta parquet files using pandas with parallel processing.
        
        Args:
            data_dir (str): Directory containing parquet files
            
        Returns:
            pandas.DataFrame: The loaded data
        """
        import pandas as pd
        import concurrent.futures
        
        def read_parquet_file(file_path):
            try:
                return pd.read_parquet(file_path)
            except Exception as e:
                self.log.warning(f"Error reading {file_path}: {str(e)}")
                return None
        
        data_files = [os.path.join(data_dir, f) for f in os.listdir(data_dir) 
                    if f.endswith('.parquet')]
        
        if not data_files:
            raise ValueError("No parquet files found in the data directory")
        
        dfs = []
        # Use parallel processing for reading files
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = executor.map(read_parquet_file, data_files)
            for result in results:
                if result is not None:
                    dfs.append(result)
        
        if not dfs:
            raise ValueError("Could not read any data files from Delta table")
        
        df = pd.concat(dfs, ignore_index=True)
        self.log.info(f"Successfully read with pandas: {len(df)} rows")
        return df
    
    def _prepare_dask_filters(self, filters):
        """
        Prepare filters for Dask.
        
        Args:
            filters (dict): Filters to apply
            
        Returns:
            list: Filters in Dask format
        """
        dask_filters = []
        if filters and isinstance(filters, dict):
            for k, v in filters.items():
                # Skip date columns at read time
                date_keywords = ['date', 'datetime', 'timestamp', 'updatedate', 'created', 'modified']
                if any(keyword in k.lower() for keyword in date_keywords):
                    continue
                    
                if isinstance(v, tuple) and len(v) == 2:
                    operator, compare_value = v
                    if operator in ['>=', '>', '<=', '<', '==', '!=']:
                        dask_filters.append((k, operator, compare_value))
                elif not isinstance(v, list):  # Skip list filters
                    dask_filters.append((k, '==', v))
        
        return dask_filters
    
    def _apply_filters(self, df, filters):
        """
        Apply filters to a DataFrame.
        
        Args:
            df (pandas.DataFrame): DataFrame to filter
            filters (dict): Filters to apply
            
        Returns:
            pandas.DataFrame: Filtered DataFrame
        """
        if df is None or not filters or not isinstance(filters, dict):
            return df
            
        rows_before = len(df)
        
        for col, val in filters.items():
            if col in df.columns:
                if isinstance(val, list):
                    # List filter
                    df = df[df[col].isin(val)]
                
                elif isinstance(val, tuple) and len(val) == 2:
                    # Comparison operators
                    operator, compare_value = val
                    
                    # Check if this is a date/time column
                    date_keywords = ['date', 'datetime', 'timestamp', 'updatedate', 'created', 'modified']
                    is_date_column = any(keyword in col.lower() for keyword in date_keywords)
                    is_datetime_column = pd.api.types.is_datetime64_any_dtype(df[col])
                    
                    if is_datetime_column or is_date_column:
                        # Simplified date handling with proper conversion
                        try:
                            # Convert column to datetime if it's not already
                            if not is_datetime_column:
                                df[col] = pd.to_datetime(df[col], errors='coerce')
                            
                            # Convert filter value to datetime
                            filter_date = pd.to_datetime(compare_value)
                            
                            # Apply the comparison
                            if operator == '>=':
                                df = df[df[col] >= filter_date]
                            elif operator == '>':
                                df = df[df[col] > filter_date]
                            elif operator == '<=':
                                df = df[df[col] <= filter_date]
                            elif operator == '<':
                                df = df[df[col] < filter_date]
                            elif operator == '!=':
                                df = df[df[col] != filter_date]
                            elif operator == '==':
                                df = df[df[col] == filter_date]
                        
                        except Exception as date_err:
                            # Fall back to string comparison if datetime fails
                            self.log.warning(f"Date conversion failed: {str(date_err)}. Falling back to string comparison.")
                            str_col = df[col].astype(str)
                            str_val = str(compare_value)
                            
                            if operator == '>=':
                                df = df[str_col >= str_val]
                            elif operator == '>':
                                df = df[str_col > str_val]
                            elif operator == '<=':
                                df = df[str_col <= str_val]
                            elif operator == '<':
                                df = df[str_col < str_val]
                            elif operator == '!=':
                                df = df[str_col != str_val]
                            elif operator == '==':
                                df = df[str_col == str_val]
                    
                    else:
                        # Regular comparison for non-date columns
                        try:
                            if operator == '>=':
                                df = df[df[col] >= compare_value]
                            elif operator == '>':
                                df = df[df[col] > compare_value]
                            elif operator == '<=':
                                df = df[df[col] <= compare_value]
                            elif operator == '<':
                                df = df[df[col] < compare_value]
                            elif operator == '!=':
                                df = df[df[col] != compare_value]
                            elif operator == '==':
                                df = df[df[col] == compare_value]
                        except Exception as op_err:
                            # Fall back to string comparison
                            self.log.warning(f"Operator comparison failed: {str(op_err)}. Falling back to string comparison.")
                            str_col = df[col].astype(str)
                            str_val = str(compare_value)
                            
                            if operator == '>=':
                                df = df[str_col >= str_val]
                            elif operator == '>':
                                df = df[str_col > str_val]
                            elif operator == '<=':
                                df = df[str_col <= str_val]
                            elif operator == '<':
                                df = df[str_col < str_val]
                            elif operator == '!=':
                                df = df[str_col != str_val]
                            elif operator == '==':
                                df = df[str_col == str_val]
                
                else:
                    # Exact match filter
                    df = df[df[col] == val]
            else:
                self.log.warning(f"Column '{col}' not found in DataFrame")
        
        self.log.info(f"Filtered from {rows_before} to {len(df)} rows")
        return df
    
    

    
    def execute_synapse_query(self, row, query, synapse_options=None):
        """
        Execute an SQL query on parquet files using Azure Synapse Serverless SQL with Service Principal authentication.
        
        Args:
            row: Row identifier (used for logging)
            query (str): SQL query to execute against the parquet files (must use OPENROWSET syntax)
            synapse_options (dict): Options for Synapse connection
                                    Required keys:
                                    - server: Synapse workspace name with .sql.azuresynapse.net
                                    - tenant_id: Azure AD tenant ID
                                    - client_id: Service principal client ID
                                    - client_secret: Service principal client secret
                                    - service_principal_name: The name to use for the service principal in SQL
        
        Returns:
            pandas.DataFrame: The query results as a DataFrame
        """
        try:
            import pyodbc
            import pandas as pd
            import struct
            from azure.identity import ClientSecretCredential
            from datetime import datetime
            
            start = datetime.now()
            self.log.info(f"Starting Synapse SQL query execution")
            
            # Validate required options
            if not synapse_options:
                raise ValueError("synapse_options is required")
                
            required_keys = ['server', 'tenant_id', 'client_id', 'client_secret', 'service_principal_name']
            missing_keys = [key for key in required_keys if key not in synapse_options]
            
            if missing_keys:
                raise ValueError(f"Missing required synapse_options: {', '.join(missing_keys)}")
            
            # Extract connection parameters
            server = synapse_options.get('server')
            tenant_id = synapse_options.get('tenant_id')
            client_id = synapse_options.get('client_id')
            client_secret = synapse_options.get('client_secret')
            service_principal_name = synapse_options.get('service_principal_name')
            
            # Log the query
            self.log.info(f"Executing Synapse query on server: {server}")
            self.log.info(f"Query: {query}")
            
            # Create credential and get token
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Get token for SQL Database
            token = credential.get_token("https://database.windows.net/.default")
            access_token = token.token
            
            # Connection string - for serverless SQL pool, connect to master database
            connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE=master;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30'
            
            # Prepare token for PyODBC
            SQL_COPT_SS_ACCESS_TOKEN = 1256
            token_bytes = access_token.encode('utf-8')
            exptoken = b''
            for i in token_bytes:
                exptoken += bytes([i])
            exptoken += bytes(1)  # Add null terminator
            tokenstruct = struct.pack("=i", len(exptoken)) + exptoken
            
            # Connect with token using attrs_before
            self.log.info(f"Connecting to Synapse serverless SQL pool")
            conn = pyodbc.connect(connection_string, attrs_before={SQL_COPT_SS_ACCESS_TOKEN: tokenstruct})
            
            # Check if the service principal login exists and create it if not
            cursor = conn.cursor()
            try:
                # Check if service principal login exists
                login_check_query = f"SELECT name FROM sys.server_principals WHERE name = '{service_principal_name}'"
                cursor.execute(login_check_query)
                login_exists = cursor.fetchone() is not None
                
                if not login_exists:
                    self.log.info(f"Creating login for service principal: {service_principal_name}")
                    # Create login from external provider
                    create_login_query = f"CREATE LOGIN [{service_principal_name}] FROM EXTERNAL PROVIDER;"
                    cursor.execute(create_login_query)
                    conn.commit()
                    
                    # Add to sysadmin role
                    add_role_query = f"ALTER SERVER ROLE sysadmin ADD MEMBER [{service_principal_name}];"
                    cursor.execute(add_role_query)
                    conn.commit()
            except Exception as e:
                self.log.warning(f"Error setting up service principal login: {str(e)}")
            
            # Execute the query
            self.log.info("Connected to Synapse. Executing query...")
            cursor.execute(query)
            
            # Fetch the results
            columns = [column[0] for column in cursor.description]
            rows = cursor.fetchall()
            
            # Convert to DataFrame
            df = pd.DataFrame.from_records(rows, columns=columns)
            
            # Close connection
            cursor.close()
            conn.close()
            
            end = datetime.now()
            self.log.info(f"Synapse query execution completed. Returned {len(df)} rows in {end-start}")
            return df
            
        except Exception as e:
            self.log.error(f"Error executing Synapse query: {str(e)}")
            raise