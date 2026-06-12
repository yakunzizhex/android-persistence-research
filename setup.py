"""
Setup configuration for Android Persistence Research Framework.

This package provides comprehensive analysis tools for studying Android
persistence mechanisms and defensive mitigations.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="android-persistence-analysis",
    version="1.0.0",
    author="Security Research Team",
    description="Comprehensive framework for analyzing Android persistence techniques",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/android-persistence-analysis",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "androguard>=4.1.2",
        "capstone>=5.0.1",
        "pycryptodomex>=3.20.0",
        "requests>=2.31.0",
        "lxml>=4.9.3",
        "cryptography>=41.0.7",
    ],
    entry_points={
        "console_scripts": [
            "android-persistence=persistence_detector:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
