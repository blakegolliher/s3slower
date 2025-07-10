from setuptools import setup, find_packages
import os
import sys

PACKAGE = "s3slower"
ROOT = os.path.dirname(__file__)
try:
    VERSION = open(os.path.join(ROOT, "version.txt")).read().strip()
except:
    VERSION = "0.0+local.dummy"
assert VERSION, "Failed to determine version"

requires = [
    "psutil>=5.8.0",
    "PyYAML>=6.0",
    "stevedore>=3.5.0",
    "prometheus_client>=0.17.0",
    "pandas>=1.3.0",
    "urllib3>=1.26.0",
    "bcc>=0.25.0",  # Requires BCC/eBPF
]

# pip install .[test]
extras_require = {
    "test": [
        "pytest>=6.2.4",
        "pytest-asyncio>=0.21.0",
    ]
}

package_data = {
    "s3slower": [
        "../s3slower.c",
        "../version.txt",
    ]
}

setup(
    name="s3slower",
    author="S3Slower Development Team",
    author_email="s3slower@example.com",
    version=VERSION,
    license="Apache License 2.0",
    description="Monitor S3 client latency using eBPF without SDK instrumentation",
    long_description="""
S3Slower is a production-ready tool for monitoring S3 client-side latency using eBPF.
It traces HTTP requests and responses from S3 clients without requiring SDK instrumentation,
providing detailed metrics via Prometheus and other exporters.

Key Features:
- eBPF-based monitoring with minimal overhead
- No application instrumentation required
- Prometheus metrics export
- S3 operation detection (GetObject, PutObject, multipart uploads, etc.)
- Process-level monitoring with PID filtering
- Configurable latency thresholds
- Multiple output formats (console, Prometheus)
    """,
    long_description_content_type="text/plain",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="s3 latency monitoring ebpf bpf aws observability prometheus",
    url="https://github.com/yourusername/s3slower",
    provides=["s3slower"],
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    package_data=package_data,
    entry_points={
        "console_scripts": [
            "s3slower = s3slower.main:main",
        ],
        "drivers": [
            "screen = s3slower.drivers:ScreenDriver",
            "prometheus = s3slower.drivers:PrometheusDriver",
        ],
    },
    install_requires=requires,
    extras_require=extras_require,
    python_requires=">=3.9",
    zip_safe=False,  # eBPF programs need to be accessible as files
) 