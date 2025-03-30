from setuptools import setup, find_packages

# EN: Read requirements from file | FR: Lecture des dépendances depuis le fichier
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    # EN: Basic package metadata | FR: Métadonnées de base du paquet
    name="log_analyzer",
    version="2.0",
    description="SOC Tool for Apache Log Analysis with Threat Detection",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="TouyA0",
    packages=find_packages(include=["log_analyzer*"]),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "log-analyzer = log_analyzer.cli:main"
        ]
    },
    package_data={
        "log_analyzer": [
            "data/*.txt",
        ]
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology"
    ],
    python_requires=">=3.6"
)