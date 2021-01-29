#!/bin/sh
{
    ## Test cloud-init
    echo "this has been written via cloud-init {exp_name}" + $(date) >> /tmp/myScript.txt
}

{
    storage_name={storage_name}
    #storage_data_path={storage_data_path}
    #storage_logs_path={storage_logs_path}
    shell_interpreter={shell_interpreter}
    remote_script_path={remote_script_path}
    script_args={script_args}
    use_gpu={use_gpu}
    terminate={terminate}
    gcp_bucket_name={gcp_bucket_name}
    gcp_bucket_path={gcp_bucket_path}
    gcp_auth_file={gcp_auth_file}
    instance_name=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-08-01&format=text")
    echo "storage_name:" $storage_name
    # echo "storage_data_path:" $storage_data_path
    # echo "storage_logs_path:" $storage_logs_path
    echo "shell_interpreter:" $shell_interpreter
    echo "remote_script:" $remote_script_path
    echo "script_args:" $script_args
    echo "use_gpu:" $use_gpu
    echo "gcp_bucket_path:" $gcp_bucket_path
    echo "gcp_bucket_name:" $gcp_bucket_name
    echo "terminate:" $terminate
    echo "instance_name:" $instance_name

    sudo apt-get update

    # Install azure command CLI
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    az login --identity

    # Install AZCopy
    wget https://aka.ms/downloadazcopy-v10-linux
    tar -xvf downloadazcopy-v10-linux
    sudo cp azcopy_linux_*/azcopy /usr/bin/
    sudo azcopy login --identity

    # ## Test azcopy
    # touch test.txt
    # sudo azcopy cp test.txt https://jerryassisted.blob.core.windows.net/assisted-ird

    # Install gsutil
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    sudo apt-get install apt-transport-https ca-certificates gnupg
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
    sudo apt-get update && sudo apt-get install google-cloud-sdk -y
    wget $gcp_auth_file
    gcloud auth activate-service-account --key-file=aerial-citron-264318-cbf5beb3284c.json


    # Install Docker
    sudo apt-get install apt-transport-https ca-certificates gnupg-agent software-properties-common -y

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
    sudo apt-get update
    sudo apt-get install docker-ce docker-ce-cli containerd.io -y

    while sudo fuser /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock >/dev/null 2>&1; do
        sleep 1
    done
    sudo apt-get install -y jq git unzip
    die() { status=$1; shift; echo "FATAL: $*"; exit $status; }
    echo "starting docker!"
    systemctl status docker.socket
    #service docker start
    echo "docker started"
    # systemctl status docker.socket
    # docker --config /home/ubuntu/.docker pull $docker_image
    echo "image pulled"

    # download script
    echo "downloading script"
    # example: https://jerryassisted.blob.core.windows.net/assisted-ird/bayestutorial.ppt
    #https://jerryassisted.blob.core.windows.net/doodad-mount/00140b70_88f9_4415_a9a4_1dc81d84eb1b.dar
    # https://storage.googleapis.com/active-ird-experiments/doodad/mount/00140b70_88f9_4415_a9a4_1dc81d84eb1b.dar
    # sudo azcopy cp https://$storage_name.blob.core.windows.net/$remote_script_path /tmp/remote_script.sh
    gsutil cp gs://$gcp_bucket_name/$remote_script_path /tmp/remote_script.sh

    # sync mount
    # Because AzureMode has no idea where the mounts are (the archive has them)
    # we just make the archive store everything into /doodad
    mkdir -p /doodad
    # storage_data_path=${storage_data_path%/}  # remove trailing slash if present
    # while /bin/true; do
    #     #  sudo azcopy sync /doodad https://jerryassisted.blob.core.windows.net/doodad-data/
    #     sudo azcopy sync /doodad https://$storage_name.blob.core.windows.net/$storage_data_path
    #     sleep 15
    # done & echo sync from /doodad to https://$storage_name.blob.core.windows.net/$storage_data_path initiated
    while /bin/true; do
        gsutil -m rsync -r /doodad gs://$gcp_bucket_name/$gcp_bucket_path/logs
        sleep 15
    done & echo sync from /doodad to gs://$gcp_bucket_name/$gcp_bucket_path/logs initiated

    # sync stdout
    # storage_logs_path=${storage_logs_path%/}  # remove trailing slash if present
    while /bin/true; do
        # # #https://jerryassisted.blob.core.windows.net/doodad-data/
        # sudo azcopy cp /tmp/user_data.log https://jerryassisted.blob.core.windows.net/doodad-logs/{instance_name}_stdout.log
        # sudo azcopy cp /tmp/user_data.log https://$storage_name.blob.core.windows.net/$storage_logs_path/${instance_name}_stdout.log
        gsutil cp /tmp/user_data.log gs://$gcp_bucket_name/$gcp_bucket_path/${instance_name}_stdout.log
        sleep 300
    done &

    if [ "$use_gpu" = "true" ]; then
        for i in {1..800}; do su -c "nvidia-modprobe -u -c=0" ubuntu && break || sleep 3; done
        systemctl start nvidia-docker
        echo 'Testing nvidia-smi'
        nvidia-smi
        echo 'Testing nvidia-smi inside docker'
        nvidia-docker run --rm $docker_image nvidia-smi
    fi

    #echo $run_script_cmd >> run_script_cmd.sh
    #bash run_script_cmd.sh
    sudo $shell_interpreter /tmp/remote_script.sh $script_args

    if [ "$terminate" = "true" ]; then
        echo "Finished experiment. Terminating"
        zone=$(curl http://metadata/computeMetadata/v1/instance/zone -H "Metadata-Flavor: Google")
        zone="${zone##*/}"
        gcloud compute instances delete $instance_name --zone $zone --quiet
    fi
} >> /tmp/user_data.log 2>&1
