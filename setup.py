from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="openssl-mcp",
    version="0.1.0",
    author="MCP Team",
    author_email="team@mcpx.dev",
    description="Model Context Protocol Server for multimedia processing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mcpx/openssl-mcp",
    packages=find_packages(where="src"),
    package_dir={"":"src"},
    entry_points={
        'console_scripts': [
            'cert-manager=src.cert_manager:main'
        ],
    },
    # 新增中文检查规则
    # Add pre-commit hook for Chinese character detection
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "mcp[cli]>=0.5.0",
        "cryptography>=41.0.0",
        "pyOpenSSL>=23.2.0",
    ],
    # 添加静态检查配置
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    extras_require={
        'dev': [
            'pre-commit==2.15.0',
            'pylint==2.12.2'
        ]
    }
)