# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="doodad",
    version="0.0.1",
    author="Jerry He (Original: Justin Fu)",
    author_email="hzyjerry@berkeley.edu",
    packages=find_packages(),
    install_requires=[
        "six",
        "boto3",
        "boto",
        "cloudpickle",
        "awscli",
        "google-api-python-client",
        "google-cloud-storage",
        "azure-storage-blob",
        "azure-identity",
        "azure-common",
        "azure-core",
        "azure-mgmt-core",
        "azure-mgmt-authorization==1.0.0",
        "azure-mgmt-compute",
        "azure-mgmt-resource==15.0.0",
        "azure-mgmt-msi==1.0.0",
        "azure-mgmt-storage",
        "azure-mgmt-network==17.1.0",
        "haikunator",
        "tqdm"
    ],
)
