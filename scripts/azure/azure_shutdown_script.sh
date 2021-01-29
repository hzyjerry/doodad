#!/bin/bash

gcp_bucket_name={gcp_bucket_name}
gcp_bucket_path={gcp_bucket_path}
instance_name=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-08-01&format=text")

gcp_bucket_path=${gcp_bucket_path%/}  # remove trailing slash if present
gsutil cp -r /doodad/* gs://$gcp_bucket_name/$gcp_bucket_path/logs
# sync stdout
gsutil cp /tmp/user_data.log gs://$gcp_bucket_name/$gcp_bucket_path/${instance_name}_stdout.log
