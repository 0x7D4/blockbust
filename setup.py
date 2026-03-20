"""
Setup configuration for blockbust
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="blockbust",
    version="0.1.0",
    description="Command-line wrapper around ZDNS with censorship detection utilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="blockbust contributors",
    url="https://github.com/qurbat/blockbust",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "blockbust=blockbust.cli:main",
        ],
    },
    python_requires=">=3.8",
)
