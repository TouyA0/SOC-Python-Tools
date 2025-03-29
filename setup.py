from setuptools import setup, find_packages

setup(
    name="soc_python_tools",
    version="0.1",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'log-analyzer=log_analyzer.log_analyzer:main',
        ],
    },
)