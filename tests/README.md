# S3Slower Test Suite

This directory contains the complete test suite for S3Slower, including unit tests, integration tests, and test documentation.

## Directory Structure

```
tests/
├── README.md              # This file - test suite overview
├── TESTING_GUIDE.md       # Detailed testing guide for S3 detection
├── conftest.py            # Shared pytest fixtures
├── test_report.html       # HTML test report (generated)
├── coverage_report/       # HTML coverage report (generated)
└── test_*.py              # Test modules
```

## Test Modules

| Module | Description | Tests |
|--------|-------------|-------|
| `test_attachment.py` | OpenSSL, GnuTLS, NSS, and HTTP attachment tests | ~40 |
| `test_config.py` | YAML configuration loading and validation | ~35 |
| `test_core_functions.py` | Core tracing and matching functions | ~45 |
| `test_correlate.py` | Log correlation functionality | ~50 |
| `test_event_handling.py` | Event processing and callbacks | ~55 |
| `test_http_parsing.py` | HTTP request/response parsing | ~40 |
| `test_metrics.py` | Prometheus metrics and aggregation | ~35 |
| `test_settings.py` | Runtime settings management | ~30 |
| `test_terminal.py` | Terminal UI and output formatting | ~15 |
| `test_utils.py` | Utility functions | ~25 |
| `test_watcher.py` | PID watcher and process classification | ~40 |

**Total: ~340 tests**

## Running Tests

### Quick Start

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests with coverage and HTML reports
pytest

# Reports are generated automatically:
# - tests/test_report.html      (test results)
# - tests/coverage_report/      (coverage report)
```

### Common Commands

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_config.py

# Run specific test class
pytest tests/test_config.py::TestConfigLoading

# Run specific test function
pytest tests/test_config.py::TestConfigLoading::test_load_yaml_config

# Run tests matching a pattern
pytest -k "http"

# Run with verbose output
pytest -v

# Run and stop on first failure
pytest -x

# Run tests by marker
pytest -m unit
pytest -m integration
pytest -m slow
```

### Test Reports

After running tests, two HTML reports are generated:

1. **Test Report** (`tests/test_report.html`)
   - Pass/fail status for all tests
   - Test duration
   - Failure details and tracebacks

2. **Coverage Report** (`tests/coverage_report/index.html`)
   - Line-by-line coverage
   - Branch coverage
   - Per-file breakdown

### Running Without Reports

If you want faster test runs without generating reports:

```bash
pytest --no-cov --no-header -q
```

## Test Coverage

Current coverage statistics:

| Module | Coverage |
|--------|----------|
| `config.py` | 94% |
| `watcher.py` | 98% |
| `exec_watch.py` | 85% |
| `core.py` | 73% |
| **Overall** | **78%** |

## Test Architecture

### Mocking Strategy

The test suite mocks the BCC (eBPF) module to enable testing without kernel access:

```python
# In conftest.py
sys.modules['bcc'] = MagicMock()
```

This allows all tests to run in any environment, including CI/CD pipelines without eBPF support.

### Fixtures

Key fixtures defined in `conftest.py`:

- `temp_dir` - Temporary directory for test files
- `sample_yaml_config` - Sample YAML configuration
- `sample_targets_config` - Sample targets with multiple clients
- `mock_proc_dir` - Mock /proc directory structure
- `sample_ops_log` - Sample operations log file
- `sample_trace_log` - Sample s3slower trace log file

## Test Markers

Tests can be marked with the following markers:

```python
@pytest.mark.unit          # Unit tests (no external dependencies)
@pytest.mark.integration   # Integration tests (may require services)
@pytest.mark.slow          # Tests that take a long time
```

Run tests by marker:

```bash
pytest -m unit           # Only unit tests
pytest -m "not slow"     # Skip slow tests
```

## Writing New Tests

### Test File Template

```python
"""Tests for module_name."""

import pytest
from unittest.mock import MagicMock, patch


class TestFeatureName:
    """Test suite for feature name."""

    def test_basic_functionality(self):
        """Test basic functionality works."""
        # Arrange
        input_data = ...

        # Act
        result = function_under_test(input_data)

        # Assert
        assert result == expected_value

    @pytest.mark.parametrize("input,expected", [
        ("case1", "result1"),
        ("case2", "result2"),
    ])
    def test_parametrized(self, input, expected):
        """Test with multiple inputs."""
        assert function(input) == expected
```

### Best Practices

1. **Descriptive test names**: Use `test_<action>_<expected_behavior>`
2. **AAA pattern**: Arrange, Act, Assert
3. **One assertion per test** (when practical)
4. **Use fixtures** for common setup
5. **Mock external dependencies** (filesystem, network, BCC)

## Continuous Integration

The test suite is designed to run in CI/CD environments:

```yaml
# Example GitHub Actions
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: pip install -r requirements-dev.txt
    - name: Run tests
      run: pytest
    - name: Upload test report
      uses: actions/upload-artifact@v4
      with:
        name: test-reports
        path: |
          tests/test_report.html
          tests/coverage_report/
```

## Troubleshooting

### Common Issues

1. **Import errors**
   ```bash
   # Make sure the package is installed
   pip install -e .
   ```

2. **BCC mock issues**
   ```bash
   # Tests should mock BCC automatically via conftest.py
   # If issues persist, ensure conftest.py is loading first
   ```

3. **Coverage not working**
   ```bash
   # Install pytest-cov
   pip install pytest-cov
   ```

4. **HTML report not generating**
   ```bash
   # Install pytest-html
   pip install pytest-html
   ```

## Additional Documentation

- See [TESTING_GUIDE.md](./TESTING_GUIDE.md) for S3 detection testing with real workloads
- See the main [README.md](../README.md) for project overview
