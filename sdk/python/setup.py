from setuptools import setup, find_packages

setup(
    name="openexecution-verify",
    version="1.0.0",
    description="OpenExecution Provenance Certificate Verification SDK",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
)
