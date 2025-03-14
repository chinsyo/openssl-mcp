from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    packages=find_packages(where="src"),
    package_dir={"":"src"},
    extras_require={
        'dev': [
            'pre-commit==2.15.0',
            'pylint==2.12.2'
        ]
    }
)