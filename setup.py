# setup.py for pip install aicm-monitor
from setuptools import setup, find_packages

setup(
    name="aicm-monitor",
    version="0.1.0",
    description="Agent Integrity & Compromise Monitor — open-source security monitoring for AI agents",
    long_description=open("README.md").read() if __import__('os').path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Gary Reinhold",
    author_email="info@centriv.ai",
    url="https://github.com/GReinhold-ai/aicm",
    license="MIT",
    packages=find_packages(),
    py_modules=["agent_sensor", "main"],
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "httpx>=0.24.0",
        "psutil>=5.9.0",
        "pydantic>=2.0.0",
        "watchdog>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "aicm-server=main:start_server",
            "aicm-sensor=agent_sensor:start_sensor",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    python_requires=">=3.9",
    keywords="ai agent security monitoring compromise detection aicm",
)
