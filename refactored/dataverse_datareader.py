import logging
import msal
import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
import yaml
from typing import Dict, List, Tuple, Optional, Union, Any

class MyDataverseReader:
    
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
            self.client_id = config['DATAVERSE']['CLIENT_ID']
            self.client_secret = config['DATAVERSE']['CLIENT_SECRET']
            self.tenant_id = config['DATAVERSE']['TENANT_ID']
        except Exception as e:
            self.log.error(f"Error loading configuration: {str(e)}")
            raise
            
        # Set higher log levels for Azure libraries
        azure_logger = "azure.core.pipeline.policies.http_logging_policy"
        logging.getLogger(azure_logger).setLevel(logging.WARNING)
        logging.getLogger('azure').setLevel(logging.WARNING)
        logging.getLogger('azure.core').setLevel(logging.WARNING)
        logging.getLogger('azure.storage').setLevel(logging.WARNING)

    def get_dataverse_connection(self,environment_url):
        try:
            # Step 1: Authenticate and get access token using MSAL
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            app = msal.ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=authority
            )
            # The scope of Dataverse API
            scopes = [f"{environment_url}/.default"]
            # Get Token
            result = app.acquire_token_for_client(scopes=scopes)
            if "access_token" not in result:
                error_message = f"Failed to obtain access token. Error {result.get('error')},{result.get('error_description')}"
                raise Exception(error_message)
            access_token = result["access_token" ]
            self.log.info(f"Dataverse {environment_url} connection Success ")
            return access_token
        except Exception as e:
            self.log.error(f"Dataverse {environment_url} connection failed with error: {e}")

    def read_dataverse_table_data(self,table_name,db_info,connection_type):
        """Updated function to query tables using EntitySetName"""
        try:
            environment_url = self.get_db_details_dataverse(db_info, connection_type)
            exclude_cols = ['@odata.etag']
            # Get access token
            access_token = self.get_dataverse_connection(environment_url)
            # Use EntitySetName for the API URL
            api_url = f"{environment_url}/api/data/v9.2/{table_name}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "OData-MaxVersion": "4.0",
                "OData-Version": "4.0",
                "Prefer": "odata.maxpagesize=5000"
            }
            # Make API Request
            response = requests.get(api_url, headers=headers)
            if response.status_code != 200:
                error_message = f"Failed to retrieve data. Status code: {response.status_code}, Message: {response.text}"
                raise Exception(error_message)
            # Process the response
            data = response.json()
            records = data.get("value", [])
            next_link = data.get("@odata.nextLink")
            # Continue fetching if there are more pages
            while next_link:
                response = requests.get(next_link, headers=headers)
                if response.status_code != 200:
                    break
                page_data = response.json()
                records.extend(page_data.get("value", []))
                next_link = page_data.get("@odata.nextLink")
            # Convert to Dataframe
            df = pd.DataFrame(records)
            df_excluded = df[[col for col in df.columns if col not in exclude_cols]]
            self.log.info(f"Retrieved {len(df.index)} records from {table_name} Dataverse table")
            return df_excluded
        except Exception as e:
            self.log.error(f"Failed retriving data for {table_name} Dataverse table with Error: {e}")
            return None
        
    def read_cid_customerprofile_data(self,table_name,db_info,connection_type):
        """Updated function to query tables using EntitySetName"""
        try:
            environment_url = self.get_db_details_dataverse(db_info, connection_type)
            exclude_cols = ['@odata.etag', 'partitionid','msdynci_customerprofileid', 'versionnumber']
            include_cols = 'msdynci_accountid,msdynci_userinfoid,msdynci_firstname,msdynci_lastname,msdynci_mobilephone,msdynci_email'
            # Get access token
            access_token = self.get_dataverse_connection(environment_url)
            # Use EntitySetName for the API URL
            api_url = f"{environment_url}/api/data/v9.2/{table_name}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "OData-MaxVersion": "4.0",
                "OData-Version": "4.0",
                "Prefer": "odata.maxpagesize=5000"
            }
            # Make API Request
            response = requests.get(api_url, headers=headers)
            if response.status_code != 200:
                error_message = f"Failed to retrieve data. Status code: {response.status_code}, Message: {response.text}"
                raise Exception(error_message)
            # Process the response
            data = response.json()
            records = data.get("value", [])
            next_link = data.get("@odata.nextLink")
            # Continue fetching if there are more pages
            while next_link:
                response = requests.get(next_link, headers=headers)
                if response.status_code != 200:
                    break
                page_data = response.json()
                records.extend(page_data.get("value", []))
                next_link = page_data.get("@odata.nextLink")
            # Convert to Dataframe
            df = pd.DataFrame(records)
            df_excluded = df[[col for col in df.columns if col not in exclude_cols]]
            self.log.info(f"Retrieved {len(df.index)} records from {table_name} Dataverse table")
            return df_excluded
        except Exception as e:
            self.log.error(f"Failed retriving data for {table_name} Dataverse table with Error: {e}")
            return None

        
    def get_db_details_dataverse(self,
        db_info: Any, 
        connection: str
    ) -> Tuple[str, str, str, str]:
        try:
            filtered_info = db_info[db_info['Project'] == connection]
            
            if filtered_info.empty:
                raise ValueError(f"No Dataverse env url details found for project: {connection}")
                
            environment_url = filtered_info.iloc[0]['Server']
            return environment_url
        except Exception as e:
            error_msg = f"Failed to get Dataverse env url details details: {e}"
            self.log.error(error_msg)
            raise ValueError(error_msg) from e
        
    def get_customerprofile_data(self,table_name,environment_url):
        """Updated function to query tables using EntitySetName"""
        try:
            exclude_cols = ['@odata.etag', 'partitionid','msdynci_customerprofileid', 'versionnumber']
            # Get access token
            access_token = self.get_dataverse_connection(environment_url)
            # Use EntitySetName for the API URL
            api_url = f"{environment_url}/api/data/v9.2/{table_name}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "OData-MaxVersion": "4.0",
                "OData-Version": "4.0",
                "Prefer": "odata.maxpagesize=5000"
            }
            # Make API Request
            response = requests.get(api_url, headers=headers)
            if response.status_code != 200:
                error_message = f"Failed to retrieve data. Status code: {response.status_code}, Message: {response.text}"
                raise Exception(error_message)
            # Process the response
            data = response.json()
            records = data.get("value", [])
            next_link = data.get("@odata.nextLink")
            # Continue fetching if there are more pages
            while next_link:
                response = requests.get(next_link, headers=headers)
                if response.status_code != 200:
                    break
                page_data = response.json()
                records.extend(page_data.get("value", []))
                next_link = page_data.get("@odata.nextLink")
            # Convert to Dataframe
            df = pd.DataFrame(records)
            df_excluded = df[[col for col in df.columns if col not in exclude_cols]]
            self.log.info(f"Retrieved {len(df.index)} records from Dataverse API")
            return df_excluded
        except Exception as e:
            self.log.error(f"Failed retriving data for {table_name} Dataverse table with Error: {e}")
            return None