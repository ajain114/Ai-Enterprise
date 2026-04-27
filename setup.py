"""
setup.py
=========
Package installation for enterprise-mcp-ai-platform.

Install in development mode:
    pip install -e .

Install for production:
    pip install .
"""

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#") and not line.startswith("-r")
    ]

setup(
    name="enterprise-mcp-ai-platform",
    version="1.0.0",
    author="Your Team",
    description=(
        "MCP server infrastructure for enterprise RAG, agentic AI, "
        "and modular data pipelines with built-in PII guardrails."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/enterprise-mcp-ai-platform",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=requirements,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    entry_points={
        "console_scripts": [
            "mcp-rag-server=src.servers.rag_server:run",
            "mcp-feature-server=src.servers.feature_store_server:run",
            "mcp-governance-server=src.servers.governance_server:run",
        ],
    },
)
