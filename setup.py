#!/usr/bin/env python3
"""Setup script for BIG-PHISH"""

from setuptools import setup, find_packages
import os
import sys

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

with open("requirements-full.txt", "r", encoding="utf-8") as f:
    dev_requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="bigphish",
    version="1.0.0",
    author="Ian Carter Kulani",
    author_email="iancarterkulani@gmail.com",
    description="Ultimate Cybersecurity & Phishing Command Center",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Iankulani/bigphish",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "monitoring": ["prometheus-client", "psutil", "pandas"],
        "dashboard": ["dash", "plotly", "flask"],
        "full": dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "bigphish=bigphish:main",
            "bigphish-cli=bigphish.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)