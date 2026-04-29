# Contributing to Agent IAM

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# 1. Fork & clone
git clone https://github.com/your-org/agent-iam.git
cd agent-iam

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
pip install ruff pytest

# 4. Copy environment config
cp .env.example .env

# 5. Start the server
python3 main.py
```

## Code Style

- **Python**: Follow PEP 8. We use `ruff` for linting.
- **JavaScript**: ES Module style, 2-space indent.
- **CSS**: CSS custom properties (variables), BEM-like naming.

## Linting & Formatting

```bash
# Lint
ruff check app/ tests/

# Auto-fix
ruff check --fix app/ tests/
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=app --cov-report=term-missing
```

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/your-feature`
2. Make your changes with clear commit messages
3. Ensure `ruff check` and `pytest` pass
4. Update documentation if needed
5. Submit a PR with a description of the changes

## Commit Messages

Use conventional commit format:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `refactor:` code refactoring
- `test:` adding tests
- `chore:` maintenance tasks

## Architecture

```
app/
├── config.py          # Pydantic settings
├── database.py        # ORM operations
├── identity.py        # Agent management
├── auth.py            # JWT authentication
├── audit.py           # Audit log + hash chain
├── policy.py          # RBAC/ABAC policy engine
├── permission.py      # Permission definitions
├── schemas.py         # Pydantic models
├── dependencies.py    # FastAPI dependencies
├── models.py          # SQLAlchemy models
├── db.py              # Connection pool config
├── ws.py              # WebSocket manager
├── routers/           # API route handlers
└── services/          # Business logic services
```

## Questions?

Open an issue on GitHub or reach out to the maintainers.
