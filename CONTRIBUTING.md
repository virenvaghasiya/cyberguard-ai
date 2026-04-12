# Contributing to CyberGuard AI

Thanks for your interest in contributing. Here's how to get started.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/cyberguard-ai.git
cd cyberguard-ai
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

We use [ruff](https://github.com/astral-sh/ruff) for linting:

```bash
pip install ruff
ruff check src/ tests/
ruff format src/ tests/
```

## Branch Strategy

- `main` — stable releases
- `develop` — active development
- Feature branches: `feature/your-feature-name`
- Bug fixes: `fix/description`

## Pull Request Process

1. Create a feature branch from `develop`
2. Write tests for new functionality
3. Ensure all tests pass and linting is clean
4. Open a PR against `develop` with a clear description
5. Wait for CI to pass and at least one review

## Adding a New Detector Module

1. Create a new file in `src/detectors/`
2. Extend `BaseDetector` from `src/core/base_detector.py`
3. Implement `start()`, `stop()`, and `analyze()` methods
4. Register it in the pipeline (see `src/api/server.py` for example)
5. Add corresponding tests in `tests/`

## Security

If you discover a security vulnerability, please do NOT open a public issue.
Email security@your-domain.com instead.
