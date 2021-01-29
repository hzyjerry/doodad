import time
import os
import json
import uuid
import base64
from azure.common.credentials import ServicePrincipalCredentials
from azure.storage.blob import BlobClient
#from azure.core.exceptions import CloudError
from haikunator import Haikunator
from doodad.apis.azure_cred_wrapper import CredentialWrapper
from doodad.apis import azure_util
from doodad.utils import hash_file, REPO_DIR, safe_import


storage = safe_import.try_import('google.cloud.storage')

AZURE_STARTUP_SCRIPT_PATH = os.path.join(REPO_DIR, "scripts/azure/azure_startup_script.sh")
AZURE_SHUTDOWN_SCRIPT_PATH = os.path.join(REPO_DIR, "scripts/azure/azure_shutdown_script.sh")
USER_ASSIGNED_IDENTITY = True
SYSTEM_ASSIGNED_IDENTITY = True


def make_timekey():
    return '%d'%(int(time.time()*1000))

def upload_file_to_azure_storage(
    credentials,
    #subscription_id,
    group_name,
    #storage_name,
    file_name,
    location='eastus',
    dry=False,
    check_exists=True
):

    if not dry:
        blob = BlobClient.from_connection_string(
            conn_str=f'https://{group_name}.blob.core.windows.net',
            container_name="doodad-mount",
            blob_name=file_name,
            credential=credentials
        )

        if check_exists and blob.exists():
            print(f"{file_name} exists.")
        else:
            with open(file_name, "rb") as data:
                blob.upload_blob(data)


def print_item(group):
    """Print a ResourceGroup instance."""
    print("\tName: {}".format(group.name))
    print("\tId: {}".format(group.id))
    if hasattr(group, 'location'):
        print("\tLocation: {}".format(group.location))
    print_properties(getattr(group, 'properties', None))


def print_properties(props):
    """Print a ResourceGroup propertyies instance."""
    if props and hasattr(props, 'provisioning_state'):
        print("\tProperties:")
        print("\t\tProvisioning State: {}".format(props.provisioning_state))
    print("\n\n")
