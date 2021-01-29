import os
import json
import uuid
import six
import time
import base64
import pprint
import shlex

from doodad.utils import shell
from doodad.utils import safe_import
from doodad import mount
from doodad.apis import azure_util
from doodad.apis.ec2.autoconfig import Autoconfig
from doodad.credentials.ec2 import AWSCredentials

googleapiclient = safe_import.try_import('googleapiclient')
googleapiclient.discovery = safe_import.try_import('googleapiclient.discovery')
boto3 = safe_import.try_import('boto3')
botocore = safe_import.try_import('botocore')
from doodad.apis import gcp_util, aws_util


class LaunchMode(object):
    """
    A LaunchMode object is responsible for executing a shell script on a specified platform.

    Args:
        shell_interpreter (str): Interpreter command for script. Default 'sh'
        async_run (bool): If True,
    """
    def __init__(self, shell_interpreter='sh', async_run=False):
        self.shell_interpreter = shell_interpreter
        self.async_run = async_run

    def run_script(self, script_filename, dry=False, return_output=False, verbose=False):
        """
        Runs a shell script.

        Args:
            script_filename (str): A string path to a shell script.
            dry (bool): If True, prints commands to be run but does not run them.
            verbose (bool): Verbose mode
            return_output (bool): If True, returns stdout from the script as a string.
        """
        if return_output:
            output = shell.call_and_get_output(self._get_run_command(script_filename), shell=True, dry=dry)
            if output:
                return output.decode('utf-8')
        else:
            shell.call(self._get_run_command(script_filename), shell=True, dry=dry, wait=not self.async_run)

    def _get_run_command(self, script_filename):
        raise NotImplementedError()

    def print_launch_message(self):
        pass


class LocalMode(LaunchMode):
    """
    A LocalMode executes commands locally using the host computer's shell interpreter.
    """
    def __init__(self, **kwargs):
        super(LocalMode, self).__init__(**kwargs)

    def __str__(self):
        return 'LocalMode'

    def _get_run_command(self, script_filename):
        return '%s %s' % (self.shell_interpreter, script_filename)


class SSHMode(LaunchMode):
    def __init__(self, ssh_credentials, **kwargs):
        super(SSHMode, self).__init__(**kwargs)
        self.ssh_cred = ssh_credentials

    def _get_run_command(self, script_filename):
        return self.ssh_cred.get_ssh_script_cmd(script_filename,
                                                shell_interpreter=self.shell_interpreter)


class EC2Mode(LaunchMode):
    def __init__(self,
                 ec2_credentials,
                 s3_bucket,
                 s3_log_path,
                 s3_log_prefix='ec2_experiment',
                 ami_name=None,
                 terminate_on_end=True,
                 region='auto',
                 instance_type='r3.nano',
                 spot_price=0.0,
                 security_group_ids=None,
                 security_groups=None,
                 aws_key_name=None,
                 iam_instance_profile_name='doodad',
                 swap_size=4096,
                 **kwargs):
        super(EC2Mode, self).__init__(**kwargs)
        self.credentials = ec2_credentials
        self.s3_bucket = s3_bucket
        self.s3_log_path = s3_log_path
        self.s3_log_prefix = s3_log_prefix
        self.ami = ami_name
        self.terminate_on_end = terminate_on_end
        self.region = region
        self.instance_type = instance_type
        self.use_gpu = False
        self.spot_price = spot_price
        self.image_id = ami_name
        self.aws_key_name = aws_key_name
        self.iam_instance_profile_name = iam_instance_profile_name
        self.security_groups = security_groups
        self.security_group_ids = security_group_ids
        self.swap_size = swap_size
        self.sync_interval = 15

    def dedent(self, s):
        lines = [l.strip() for l in s.split('\n')]
        return '\n'.join(lines)

    def run_script(self, script_name, dry=False, return_output=False, verbose=False):
        assert not return_output

        default_config = dict(
            image_id=self.image_id,
            instance_type=self.instance_type,
            key_name=self.aws_key_name,
            spot_price=self.spot_price,
            iam_instance_profile_name=self.iam_instance_profile_name,
            security_groups=self.security_groups,
            security_group_ids=self.security_group_ids,
            network_interfaces=[],
        )
        aws_config = dict(default_config)
        time_key = gcp_util.make_timekey()
        exp_name = "{}-{}".format(self.s3_log_prefix, time_key)
        exp_prefix = self.s3_log_prefix

        s3_base_dir = os.path.join(self.s3_log_path, exp_prefix.replace("_", "-"), exp_name)
        s3_log_dir = os.path.join(s3_base_dir, 'logs')
        stdout_log_s3_path = os.path.join(s3_base_dir, 'stdout_$EC2_INSTANCE_ID.log')

        sio = six.StringIO()
        sio.write("#!/bin/bash\n")
        sio.write("truncate -s 0 /home/ubuntu/user_data.log\n")
        sio.write("{\n")
        sio.write('die() { status=$1; shift; echo "FATAL: $*"; exit $status; }\n')
        sio.write('EC2_INSTANCE_ID="`wget -q -O - http://169.254.169.254/latest/meta-data/instance-id`"\n')
        sio.write("""
            aws ec2 create-tags --resources $EC2_INSTANCE_ID --tags Key=Name,Value={exp_name} --region {aws_region}
        """.format(exp_name=exp_name, aws_region=self.region))
        sio.write("""
            aws ec2 create-tags --resources $EC2_INSTANCE_ID --tags Key=exp_prefix,Value={exp_prefix} --region {aws_region}
        """.format(exp_prefix=exp_prefix, aws_region=self.region))

        # Add swap file
        if self.use_gpu:
            swap_location = '/mnt/swapfile'
        else:
            swap_location = '/var/swap.1'
        sio.write(
            'sudo dd if=/dev/zero of={swap_location} bs=1M count={swap_size}\n'
            .format(swap_location=swap_location, swap_size=self.swap_size))
        sio.write('sudo mkswap {swap_location}\n'.format(swap_location=swap_location))
        sio.write('sudo chmod 600 {swap_location}\n'.format(swap_location=swap_location))
        sio.write('sudo swapon {swap_location}\n'.format(swap_location=swap_location))

        sio.write("service docker start\n")
        #sio.write("docker --config /home/ubuntu/.docker pull {docker_image}\n".format(docker_image=self.docker_image))
        sio.write("export AWS_DEFAULT_REGION={aws_region}\n".format(aws_region=self.s3_bucket))
        sio.write("""
            curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
            unzip awscli-bundle.zip
            sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
        """)

        # 1) Upload script and download it to remote
        aws_util.s3_upload(script_name, self.s3_bucket, 'doodad/mount', dry=dry)
        script_s3_filename = 's3://{bucket_name}/doodad/mount/{script_name}'.format(
            bucket_name=self.s3_bucket,
            script_name=script_name
        )
        sio.write('aws s3 cp {script_s3_filename} /tmp/remote_script.sh\n'.format(
            script_s3_filename=script_s3_filename
        ))

        # 2) Sync data
        # In theory the ec2_local_dir could be some random directory,
        # but we make it the same as the mount directory for
        # convenience.
        #
        # ec2_local_dir: directory visible to ec2 spot instance
        # moint_point: directory visible to docker running inside ec2
        #               spot instance
        ec2_local_dir = '/doodad'

        # Sync interval
        sio.write("""
        while /bin/true; do
            aws s3 sync --exclude '*' {include_string} {log_dir} {s3_path}
            sleep {periodic_sync_interval}
        done & echo sync initiated
        """.format(
            include_string='',
            log_dir=ec2_local_dir,
            s3_path=s3_log_dir,
            periodic_sync_interval=self.sync_interval
        ))

        # Sync on terminate. This catches the case where the spot
        # instance gets terminated before the user script ends.
        #
        # This is hoping that there's at least 3 seconds between when
        # the spot instance gets marked for  termination and when it
        # actually terminates.
        sio.write("""
            while /bin/true; do
                if [ -z $(curl -Is http://169.254.169.254/latest/meta-data/spot/termination-time | head -1 | grep 404 | cut -d \  -f 2) ]
                then
                    logger "Running shutdown hook."
                    aws s3 cp --recursive {log_dir} {s3_path}
                    aws s3 cp /home/ubuntu/user_data.log {stdout_log_s3_path}
                    break
                else
                    # Spot instance not yet marked for termination.
                    # This is hoping that there's at least 3 seconds
                    # between when the spot instance gets marked for
                    # termination and when it actually terminates.
                    sleep 3
                fi
            done & echo log sync initiated
        """.format(
            log_dir=ec2_local_dir,
            s3_path=s3_log_dir,
            stdout_log_s3_path=stdout_log_s3_path,
        ))

        sio.write("""
        while /bin/true; do
            aws s3 cp /home/ubuntu/user_data.log {stdout_log_s3_path}
            sleep {periodic_sync_interval}
        done & echo sync initiated
        """.format(
            stdout_log_s3_path=stdout_log_s3_path,
            periodic_sync_interval=self.sync_interval
        ))

        if self.use_gpu:
            sio.write("""
                for i in {1..800}; do su -c "nvidia-modprobe -u -c=0" ubuntu && break || sleep 3; done
                systemctl start nvidia-docker
            """)
            sio.write("echo 'Testing nvidia-smi'\n")
            sio.write("nvidia-smi\n")
            sio.write("echo 'Testing nvidia-smi inside docker'\n")
            #sio.write("nvidia-docker run --rm {docker_image} nvidia-smi\n".format(docker_image=self.docker_image))

        #docker_cmd = self.get_docker_cmd(main_cmd, use_tty=False, extra_args=mnt_args, pythonpath=py_path, use_docker_generated_name=True)

        docker_cmd = '%s /tmp/remote_script.sh' % self.shell_interpreter
        sio.write(docker_cmd+'\n')

        # Sync all output mounts to s3 after running the user script
        # Ideally the earlier while loop would be sufficient, but it might be
        # the case that the earlier while loop isn't fast enough to catch a
        # termination. So, we explicitly sync on termination.
        sio.write("aws s3 cp --recursive {local_dir} {s3_dir}\n".format(
            local_dir=ec2_local_dir,
            s3_dir=s3_log_dir
        ))
        sio.write("aws s3 cp /home/ubuntu/user_data.log {}\n".format(
            stdout_log_s3_path,
        ))

        if self.terminate_on_end:
            sio.write("""
                EC2_INSTANCE_ID="`wget -q -O - http://169.254.169.254/latest/meta-data/instance-id || die \"wget instance-id has failed: $?\"`"
                aws ec2 terminate-instances --instance-ids $EC2_INSTANCE_ID --region {aws_region}
            """.format(aws_region=self.region))
        sio.write("} >> /home/ubuntu/user_data.log 2>&1\n")

        full_script = self.dedent(sio.getvalue())
        ec2 = boto3.client(
            "ec2",
            region_name=self.region,
            aws_access_key_id=self.credentials.aws_key,
            aws_secret_access_key=self.credentials.aws_secret_key,
        )

        if len(full_script) > 10000 or len(base64.b64encode(full_script.encode()).decode("utf-8")) > 10000:
            s3_path = aws_util.s3_upload(full_script, self.s3_bucket, 'doodad/mount', dry=dry)
            sio = six.StringIO()
            sio.write("#!/bin/bash\n")
            sio.write("""
            aws s3 cp {s3_path} /home/ubuntu/remote_script.sh --region {aws_region} && \\
            chmod +x /home/ubuntu/remote_script.sh && \\
            bash /home/ubuntu/remote_script.sh
            """.format(s3_path=s3_path, aws_region=self.s3_bucket))
            user_data = self.dedent(sio.getvalue())
        else:
            user_data = full_script

        if verbose:
            print(full_script)
            with open("/tmp/full_ec2_script", "w") as f:
                f.write(full_script)

        instance_args = dict(
            ImageId=aws_config["image_id"],
            KeyName=aws_config["key_name"],
            UserData=user_data,
            InstanceType=aws_config["instance_type"],
            EbsOptimized=False,
            SecurityGroups=aws_config["security_groups"],
            SecurityGroupIds=aws_config["security_group_ids"],
            NetworkInterfaces=aws_config["network_interfaces"],
            IamInstanceProfile=dict(
                Name=aws_config["iam_instance_profile_name"],
            ),
            #**config.AWS_EXTRA_CONFIGS,
        )

        if verbose:
            print("************************************************************")
            print('UserData:', instance_args["UserData"])
            print("************************************************************")
        instance_args["UserData"] = base64.b64encode(instance_args["UserData"].encode()).decode("utf-8")
        spot_args = dict(
            DryRun=dry,
            InstanceCount=1,
            LaunchSpecification=instance_args,
            SpotPrice=aws_config["spot_price"],
            # ClientToken=params_list[0]["exp_name"],
        )

        if verbose:
            pprint.pprint(spot_args)
        if not dry:
            response = ec2.request_spot_instances(**spot_args)
            print('Launched EC2 job - Server response:')
            pprint.pprint(response)
            print('*****'*5)
            spot_request_id = response['SpotInstanceRequests'][
                0]['SpotInstanceRequestId']
            for _ in range(10):
                try:
                    ec2.create_tags(
                        Resources=[spot_request_id],
                        Tags=[
                            {'Key': 'Name', 'Value': exp_name}
                        ],
                    )
                    break
                except botocore.exceptions.ClientError:
                    continue


class EC2Autoconfig(EC2Mode):
    def __init__(self,
            autoconfig_file=None,
            region='us-west-1',
            s3_bucket=None,
            ami_image=None,
            aws_key_name=None,
            iam_instance_profile_name=None,
            **kwargs
            ):
        # find config file
        autoconfig = Autoconfig(autoconfig_file)
        s3_bucket = autoconfig.s3_bucket() if s3_bucket is None else s3_bucket
        image_id = autoconfig.aws_image_id(region) if ami_image is None else ami_image
        aws_key_name= autoconfig.aws_key_name(region) if aws_key_name is None else aws_key_name
        iam_profile= autoconfig.iam_profile_name() if iam_instance_profile_name is None else iam_instance_profile_name
        credentials=AWSCredentials(aws_key=autoconfig.aws_access_key(), aws_secret=autoconfig.aws_access_secret())
        security_group_ids = autoconfig.aws_security_group_ids()[region]
        security_groups = autoconfig.aws_security_groups()

        super(EC2Autoconfig, self).__init__(
                s3_bucket=s3_bucket,
                ami_name=image_id,
                aws_key_name=aws_key_name,
                iam_instance_profile_name=iam_profile,
                ec2_credentials=credentials,
                region=region,
                security_groups=security_groups,
                security_group_ids=security_group_ids,
                **kwargs
                )

class AzureMode(LaunchMode):
    """
    Azure Launch Mode.

    Args:
        azure_storage (str): Azure Bucket for storing logs and data
        azure_group_name (str): Name of the azure project.
        disk_size (int): Amount of disk to allocate to instance in Gb.
        terminate_on_end (bool): Terminate instance when script finishes
        preemptible (bool): Start a preemptible instance
        zone (str): Azure compute zone.
        instance_type (str): Azure instance type

    Deprecated:
        azure_log_path (str): Path under Azure bucket to store logs/data.
            The full path will be of the form:
            https://{azure_storage}.blob.core.windows.net/{azure_log_path}

    Example:
        azure_group_name: 'jerry-assisted-reward-design'
    """

    def __init__(self,
                 azure_storage,
                 azure_group_name='ubuntu-os-cloud',
                 #azure_image='ubuntu-1804-bionic-v20181222',
                 disk_size=64,
                 terminate_on_end=True,
                 instance_type='f1-micro',
                 azure_label='azure_doodad',
                 # storage_data_path='doodad-data',
                 # storage_logs_path='doodad-logs',
                 gcp_bucket_name="",
                 gcp_bucket_path="",
                 gcp_auth_file="",
                 location='eastus',
                 username='doodad',
                 password='doodad@123',
                 **kwargs):
        from azure.identity import DefaultAzureCredential

        super(AzureMode, self).__init__(**kwargs)
        self.azure_storage = azure_storage
        # self.azure_image = azure_image
        self.azure_group_name = azure_group_name
        self.disk_size = disk_size
        self.terminate_on_end = terminate_on_end
        self.use_gpu = False
        self.azure_label = azure_label
        # self.storage_data_path = storage_data_path
        # self.storage_logs_path = storage_logs_path
        self.gcp_bucket_path = gcp_bucket_path
        self.gcp_bucket_name = gcp_bucket_name
        self.gcp_auth_file = gcp_auth_file
        self.location = location
        self.username = username
        self.password = password
        # instance name must match regex '(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)'">
        self.unique_name= "doodad" + str(uuid.uuid4()).replace("-", "")

        ## Credentials
        self.subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "<subscription_id>")
        self.cred_wrapper = azure_util.CredentialWrapper()
        self.credentials = DefaultAzureCredential()

        self.vm_reference = {
            'linux': {
                'publisher': 'Canonical',
                'offer': 'UbuntuServer',
                'sku': '16.04.0-LTS',
                'version': 'latest'
            }
        }

    def __str__(self):
        return 'Azure-%s' % (self.azure_group_name)

    def print_launch_message(self):
        pass

    def run_script(self, script, dry=False, return_output=False, verbose=False, wait=False):
        if return_output:
            raise NotImplementedError()

        print("Creating network")
        t1 = time.time()
        nic_id = self.create_network()
        print("Created network", time.time() - t1)

        # Upload script to GCS
        cmd_split = shlex.split(script)
        script_fname = cmd_split[0]
        if len(cmd_split) > 1:
            script_args = ' '.join(cmd_split[1:])
        else:
            script_args = ''
        # remote_script = azure_util.upload_file_to_azure_storage(
        #     credentials=self.credentials,
        #     #subscription_id=self.subscription_id,
        #     group_name=self.azure_group_name,
        #     #storage_name=self.azure_storage,
        #     location=self.location,
        #     file_name=script_fname,
        #     dry=dry)
        remote_script_path = gcp_util.upload_file_to_gcp_storage(self.gcp_bucket_name, script_fname, dry=dry)

        exp_name = "{}-{}".format(self.azure_label, azure_util.make_timekey())
        exp_prefix = self.azure_label

        with open(azure_util.AZURE_STARTUP_SCRIPT_PATH) as f:
            start_script = self.process_script(f.read(), script_args, remote_script_path=remote_script_path)
        with open(azure_util.AZURE_SHUTDOWN_SCRIPT_PATH) as f:
            stop_script = self.process_script(f.read())

        print("Creating msi")
        t1 = time.time()
        msi_identity = self.create_msi()
        print("Created msi", time.time() - t1)

        vm_parameters = {
            'location': self.location,
            'os_profile': {
                'computer_name': self.unique_name,
                'admin_username': self.username,
                'admin_password': self.password,
                'custom_data': start_script,
            },
            'hardware_profile': {
                #'vm_size': 'Standard_DS1'
                'vm_size': 'STANDARD_D4_V3'
            },
            'storage_profile': {
                'image_reference': {
                    'publisher': self.vm_reference['linux']['publisher'],
                    'offer': self.vm_reference['linux']['offer'],
                    'sku': self.vm_reference['linux']['sku'],
                    'version': self.vm_reference['linux']['version']
                },
                # 'os_disk': {
                #     'name': unique_name + '-osdisk',
                #     'caching': 'None',
                #     'create_option': 'Empty',
                #     # 'create_option': 'fromImage',
                #     # 'vhd': {
                #     #     'uri': 'https://jerryassisted.blob.core.windows.net/vhds/jerry-assisted-reward-designsoft-paper-2857.vhd'
                #     #     # 'uri': 'https://{}.blob.core.windows.net/vhds/{}.vhd'.format(
                #     #     #     self.azure_storage, unique_name+haikunator.haikunate())
                #     # }
                # },
            },
            'network_profile': {
                'network_interfaces': [{
                    'id': nic_id,
                }]
            },
            'identity': msi_identity
        }
        print("Creating vm")
        t1 = time.time()
        vm_result = self.create_instance(vm_parameters, self.unique_name, exp_name, exp_prefix, dry=dry, wait=wait)
        print("Created vm", time.time() - t1)

        if verbose:
            print('Launched instance %s' % self.unique_name)
        return vm_result

    def create_msi(self):
        '''Assign Azure identity'''
        ### Enable MSI
        from azure.mgmt.msi import ManagedServiceIdentityClient
        from azure.mgmt.compute.models import ResourceIdentityType

        params_identity = {'principal_id': []}
        msi_client = ManagedServiceIdentityClient(self.cred_wrapper, self.subscription_id)
        if azure_util.USER_ASSIGNED_IDENTITY:
            # Create a User Assigned Identity if needed
            print("\nCreate User Assigned Identity")
            user_assigned_identity = msi_client.user_assigned_identities.create_or_update(
                self.azure_group_name,
                "myMsiIdentity",  # Any name, just a human readable ID
                self.location
            )
            params_identity['principal_id'].append(user_assigned_identity.principal_id)
            azure_util.print_item(user_assigned_identity)
        if azure_util.USER_ASSIGNED_IDENTITY and azure_util.SYSTEM_ASSIGNED_IDENTITY:
            params_identity['type'] = ResourceIdentityType.system_assigned_user_assigned
            params_identity['user_assigned_identities'] = {
                user_assigned_identity.id: {}
            }
        elif azure_util.USER_ASSIGNED_IDENTITY:  # User Assigned only
            params_identity['type'] = ResourceIdentityType.user_assigned
            params_identity['user_assigned_identities'] = {
                user_assigned_identity.id: {}
            }
        elif azure_util.SYSTEM_ASSIGNED_IDENTITY:  # System assigned only
            params_identity['type'] = ResourceIdentityType.system_assigned
        return params_identity

    def process_script(self, raw_script, script_args='', remote_script_path=''):
        start_script = raw_script.replace("{exp_name}", "123")
        start_script = start_script.replace("{storage_name}", self.azure_storage)
        # start_script = start_script.replace("{storage_logs_path}", self.storage_logs_path)
        # start_script = start_script.replace("{storage_data_path}", self.storage_data_path)
        start_script = start_script.replace("{shell_interpreter}", self.shell_interpreter)
        start_script = start_script.replace("{remote_script_path}", remote_script_path)
        start_script = start_script.replace("{gcp_bucket_path}", self.gcp_bucket_path)
        start_script = start_script.replace("{gcp_bucket_name}", self.gcp_bucket_name)
        start_script = start_script.replace("{gcp_auth_file}", self.gcp_auth_file)
        start_script = start_script.replace("{script_args}", script_args)
        start_script = start_script.replace("{terminate}", json.dumps(self.terminate_on_end))
        start_script = start_script.replace("{use_gpu}", json.dumps(self.use_gpu))
        print("script length", len(base64.b64encode(start_script.encode()).decode("utf-8")))
        return base64.b64encode(start_script.encode()).decode("utf-8")

    def create_instance(self, vm_parameters, name, exp_name="", exp_prefix="", dry=False, wait=False):
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.resource import ResourceManagementClient

        resource_client = ResourceManagementClient(self.credentials, self.subscription_id)
        compute_client = ComputeManagementClient(self.credentials, self.subscription_id)

        # Create Resource Group
        rg_update = resource_client.resource_groups.create_or_update(self.azure_group_name, {'location': self.location})

        # Read script
        with open(azure_util.AZURE_STARTUP_SCRIPT_PATH) as f:
            raw_script = f.read()
        async_vm_creation = compute_client.virtual_machines.begin_create_or_update(self.azure_group_name, name, vm_parameters)


        # ### Assign MSI role
        # msi_accounts_to_assign = []
        # if azure_util.SYSTEM_ASSIGNED_IDENTITY:
        #     msi_accounts_to_assign.append(vm_result.identity.principal_id)
        # if azure_util.USER_ASSIGNED_IDENTITY:
        #     msi_accounts_to_assign.append(user_assigned_identity.principal_id)

        # ### Get "Contributor" built-in role as a RoleDefinition object
        # role_names = ['Contributor', 'Storage Blob Data Contributor']
        # roles = []
        # for name in role_names:
        #     roles += list(authorization_client.role_definitions.list(rg_update.id, filter="roleName eq '{}'".format(name)))

        # ### Add RG scope to the MSI token
        # for msi_identity in msi_accounts_to_assign:
        #     for role in roles:
        #         try:
        #             role_assignment = authorization_client.role_assignments.create(
        #                 rg_update.id,
        #                 uuid.uuid4(), # Role assignment random name
        #                 {
        #                     'role_definition_id': role.id,
        #                     'principal_id': msi_identity
        #                 }
        #             )
        #         except Exception as e:
        #             print("Error", e)

        # # Tag the VM
        # async_vm_update = compute_client.virtual_machines.begin_create_or_update(
        #     self.azure_group_name,
        #     name,
        #     {
        #         'location': self.location,
        #         'tags': {
        #             'who-rocks': 'python',
        #             'where': 'on azure'
        #         }
        #     }
        # )
        # try:
        #     async_vm_update.wait()
        # except Exception as e:
        #     print("Status", async_vm_update.status())
        #     print("Error", e)

        if wait:
            try:
                async_vm_creation.wait()
            except Exception as e:
                print("Status", async_vm_creation.status())
                print("Error", e)
                return
            vm_result = async_vm_creation.result()
            return vm_result
        else:
            return async_vm_creation
        #return vm_result


    def create_network(self):
        from azure.mgmt.network import NetworkManagementClient

        # network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        network_client = NetworkManagementClient(
            credential=self.credentials,
            subscription_id=self.subscription_id
        )
        nic_name = self.unique_name + '-nic'
        subnet_name = self.unique_name + '-subnet'

        vnet_name = self.unique_name + '-vnet'
        ip_name = self.azure_group_name + '-ip'
        ip_config_name = self.azure_group_name + '-ip-config'

        async_vnet_creation = network_client.virtual_networks.begin_create_or_update(
            self.azure_group_name,
            vnet_name,
            {
                'location': self.location,
                'address_space': {
                    'address_prefixes': ['10.0.0.0/16']
                }
            }
        )
        async_vnet_creation.wait()
        # Create Subnet
        async_subnet_creation = network_client.subnets.begin_create_or_update(
            self.azure_group_name,
            vnet_name,
            subnet_name,
            {'address_prefix': '10.0.0.0/24'}
        )
        subnet_info = async_subnet_creation.result()
        # Create IP
        # async_ip_creation = network_client.public_ip_addresses.begin_create_or_update(self.azure_group_name,
        #     ip_name,
        #     {
        #         "location": self.location,
        #         "sku": { "name": "Standard" },
        #         "public_ip_allocation_method": "Static",
        #         "public_ip_address_version" : "IPV4"
        #     }
        # )
        # ip_address_result = async_ip_creation.result()
        # Create NIC
        async_nic_creation = network_client.network_interfaces.begin_create_or_update(
            self.azure_group_name,
            nic_name,
            {
                'location': self.location,
                'ip_configurations': [{
                    'name': ip_config_name,
                    'subnet': {
                        'id': subnet_info.id
                    },
                    # "public_ip_address": {"id": ip_address_result.id }
                }]
            }
        )
        # result = async_nic_creation.result()
        # return result.id
        return f'/subscriptions/{self.subscription_id}/resourceGroups/{self.azure_group_name}/providers/Microsoft.Network/networkInterfaces/' + nic_name

class GCPMode(LaunchMode):
    """
    GCP Launch Mode.

    Args:
        gcp_project (str): Name of GCP project to launch from
        gcp_bucket (str): GCP Bucket for storing logs and data
        gcp_log_path (str): Path under GCP bucket to store logs/data.
            The full path will be of the form:
            gs://{gcp_bucket}/{gcp_log_path}
        gcp_image (str): Name of GCE image from which to base instance.
        gcp_image_project (str): Name of project gce_image belongs to.
        disk_size (int): Amount of disk to allocate to instance in Gb.
        terminate_on_end (bool): Terminate instance when script finishes
        preemptible (bool): Start a preemptible instance
        zone (str): GCE compute zone.
        instance_type (str): GCE instance type
    """
    def __init__(self,
                 gcp_project,
                 gcp_bucket,
                 gcp_log_path,
                 gcp_image='ubuntu-1804-bionic-v20181222',
                 gcp_image_project='ubuntu-os-cloud',
                 disk_size=64,
                 terminate_on_end=True,
                 preemptible=True,
                 zone='auto',
                 instance_type='f1-micro',
                 gcp_label='gcp_doodad',
                 **kwargs):
        super(GCPMode, self).__init__(**kwargs)
        self.gcp_project = gcp_project
        self.gcp_bucket = gcp_bucket
        self.gcp_log_path = gcp_log_path
        self.gce_image = gcp_image
        self.gce_image_project = gcp_image_project
        self.disk_size = disk_size
        self.terminate_on_end = terminate_on_end
        self.preemptible = preemptible
        self.zone = zone
        self.instance_type = instance_type
        self.use_gpu = False
        self.gcp_label = gcp_label
        self.compute = googleapiclient.discovery.build('compute', 'v1')

    def __str__(self):
        return 'GCP-%s-%s' % (self.gcp_project, self.instance_type)

    def print_launch_message(self):
        print('Go to https://console.cloud.google.com/compute to monitor jobs.')

    def run_script(self, script, dry=False, return_output=False, verbose=False):
        if return_output:
            raise NotImplementedError()

        # Upload script to GCS
        cmd_split = shlex.split(script)
        script_fname = cmd_split[0]
        if len(cmd_split) > 1:
            script_args = ' '.join(cmd_split[1:])
        else:
            script_args = ''
        remote_script = gcp_util.upload_file_to_gcp_storage(self.gcp_bucket, script_fname, dry=dry)

        exp_name = "{}-{}".format(self.gcp_label, gcp_util.make_timekey())
        exp_prefix = self.gcp_label

        with open(gcp_util.GCP_STARTUP_SCRIPT_PATH) as f:
            start_script = f.read()
        with open(gcp_util.GCP_SHUTDOWN_SCRIPT_PATH) as f:
            stop_script = f.read()

        metadata = {
            'shell_interpreter': self.shell_interpreter,
            'gcp_bucket_path': self.gcp_log_path,
            'remote_script_path': remote_script,
            'bucket_name': self.gcp_bucket,
            'terminate': json.dumps(self.terminate_on_end),
            'use_gpu': self.use_gpu,
            'script_args': script_args,
            'startup-script': start_script,
            'shutdown-script': stop_script
        }
        # instance name must match regex '(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)'">
        unique_name= "doodad" + str(uuid.uuid4()).replace("-", "")
        instance_info = self.create_instance(metadata, unique_name, exp_name, exp_prefix, dry=dry)
        if verbose:
            print('Launched instance %s' % unique_name)
            print(instance_info)
        return metadata

    def create_instance(self, metadata, name, exp_name="", exp_prefix="", dry=False):
        compute_images = self.compute.images().get(
            project=self.gce_image_project,
            image=self.gce_image,
        )
        if not dry:
            image_response = compute_images.execute()
        else:
            image_response = {'selfLink': None}
        source_disk_image = image_response['selfLink']
        if self.zone == 'auto':
            raise NotImplementedError('auto zone finder')
        zone = self.zone

        config = {
            'name': name,
            'machineType': gcp_util.get_machine_type(zone, self.instance_type),
            'disks': [{
                    'boot': True,
                    'autoDelete': True,
                    'initializeParams': {
                        'sourceImage': source_disk_image,
                        'diskSizeGb': self.disk_size,
                    }
            }],
            'networkInterfaces': [{
                'network': 'global/networks/default',
                'accessConfigs': [
                    {'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT'}
                ]
            }],
            'serviceAccounts': [{
                'email': 'default',
                'scopes': ['https://www.googleapis.com/auth/cloud-platform']
            }],
            'metadata': {
                'items': [
                    {'key': key, 'value': value}
                    for key, value in metadata.items()
                ]
            },
            'scheduling': {
                "onHostMaintenance": "terminate",
                "automaticRestart": False,
                "preemptible": self.preemptible,
            },
            "labels": {
                "exp_name": exp_name,
                "exp_prefix": exp_prefix,
            }
        }
        compute_instances = self.compute.instances().insert(
            project=self.gcp_project,
            zone=zone,
            body=config
        )
        if not dry:
            return compute_instances.execute()
