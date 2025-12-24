Name:           s3slower
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        eBPF-based S3 latency tracer

License:        MIT
URL:            https://github.com/blakegolliher/s3slower
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       python3
Requires:       bcc
Requires:       python3-bcc

# Optional but recommended
Recommends:     python3-pyyaml
Recommends:     python3-prometheus_client

%description
s3slower uses eBPF to trace S3 API request latency at the TLS and plain HTTP
layers. It provides deep visibility into S3-compatible storage systems without
modifying application code.

Features:
- TLS-level tracing via OpenSSL, GnuTLS, and NSS
- Plain HTTP tracing via syscall probes
- Per-operation latency statistics (p50, p90, p99)
- Prometheus metrics export
- Auto-attach watch mode for dynamic process tracing

%prep
%setup -q

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/%{name}
mkdir -p %{buildroot}%{_datadir}/%{name}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}/opt/%{name}

# Install main script
install -m 755 s3slower.py %{buildroot}%{_bindir}/s3slower

# Install Python package
cp -r s3slower %{buildroot}%{_datadir}/%{name}/

# Install config
install -m 644 packaging/config.yaml %{buildroot}%{_sysconfdir}/%{name}/config.yaml

# Install docs
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/
install -m 644 LICENSE %{buildroot}%{_docdir}/%{name}/
install -m 644 requirements.txt %{buildroot}%{_docdir}/%{name}/

%post
# Create log directory
mkdir -p /opt/%{name}
chmod 755 /opt/%{name}

%files
%license LICENSE
%doc README.md requirements.txt
%{_bindir}/s3slower
%{_datadir}/%{name}/
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml
%dir /opt/%{name}

%changelog
* Tue Jan 01 2025 s3slower contributors <blakegolliher.s3slower@gmail.com> - 0.2.0
- Modular package structure
- Added curl and boto3 test scripts
- Plain HTTP tracing support
- Prometheus metrics with customizable labels

* Sun Dec 01 2024 s3slower contributors <blakegolliher.s3slower@gmail.com> - 0.1.0
- Initial release
