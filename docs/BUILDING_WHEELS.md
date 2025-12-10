# Building Wheels for Multiple Platforms

This project is configured to build wheels for Linux, macOS, and Windows.

## Automated Building with GitHub Actions

The `.github/workflows/build-wheels.yml` workflow automatically builds wheels for all platforms when you:

- Push to the `main` branch
- Create a release tag (e.g., `v0.1.0`)
- Manually trigger the workflow

## Manual Building

### Using Local Build Script

```bash
# Build for current platform
./scripts/build-wheels.sh
```

### Using Maturin Directly

```bash
# Install maturin
pip install maturin

# Build release wheel for current platform
maturin build --release

# Build wheels for multiple Python versions
maturin build --release --interpreter python3.8 python3.9 python3.10 python3.11 python3.12
```

### Cross-Compilation

#### For Linux (using Docker)

```bash
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release --manylinux 2014
```

#### For macOS (universal2)

```bash
# On macOS with both architectures
maturin build --release --target universal2-apple-darwin
```

#### For Windows

```bash
# On Windows
maturin build --release
```

## Platform-Specific Notes

### Linux

- Builds use manylinux2014 for compatibility
- Wheels are compatible with most modern Linux distributions

### macOS

- Universal2 wheels support both Intel and Apple Silicon
- Minimum supported macOS version: 10.12

### Windows

- Requires Visual Studio Build Tools or MSVC
- Supports Windows 10 and later

## Testing Wheels

After building, test the wheel:

```bash
# Create a test environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install the wheel
pip install target/wheels/cedar_py-*.whl

# Test import
python -c "import cedar_py; print(cedar_py.__version__)"
```

## Distribution

### PyPI

To publish to PyPI (done automatically by CI on release):

```bash
maturin publish
```

### Manual Distribution

Wheels are saved in `target/wheels/` and can be distributed directly.

## Troubleshooting

### Rust Not Found

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Failures

- Ensure all dependencies are installed
- Check that Rust version is up to date: `rustup update`
- For platform-specific issues, consult the maturin documentation
