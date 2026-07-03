```markdown
# turnstile Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and conventions used in the `turnstile` Python codebase. You'll learn about file naming, import/export styles, commit message habits, and how to structure and run tests. While no specific frameworks or automated workflows are detected, this guide will help you contribute code that fits seamlessly with the existing project style.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `userAuth.py`, `dataProcessor.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .utils import parseInput
    from .models import TurnstileModel
    ```

### Export Style
- Use **named exports** (explicitly specify what is exported).
  - Example:
    ```python
    __all__ = ['Turnstile', 'TurnstileError']
    ```

### Commit Patterns
- Commit messages are **freeform** (no enforced prefix), but tend to be concise (average 63 characters).
  - Example:  
    ```
    Fix bug in user authentication logic
    ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add new functionality as a separate module  
**Command:** `/add-module`

1. Create a new file using camelCase (e.g., `featureX.py`).
2. Implement your logic, using relative imports for dependencies.
3. Define `__all__` to specify exports.
4. Write corresponding tests in a `*.test.*` file.
5. Commit your changes with a clear, concise message.

### Writing and Running Tests
**Trigger:** When you add or modify code and need to ensure correctness  
**Command:** `/run-tests`

1. Create a test file named with `.test.` in the filename (e.g., `featureX.test.py`).
2. Write test cases using your preferred testing framework (none enforced).
3. Run the tests manually with your chosen test runner (e.g., `python featureX.test.py`).
4. Review results and fix any failures.

## Testing Patterns

- Test files are named with the pattern `*.test.*` (e.g., `module.test.py`).
- No specific testing framework is enforced; you may use `unittest`, `pytest`, or simple assert statements.
- Place test files alongside the modules they test or in a dedicated test directory if present.

**Example test file:**
```python
# featureX.test.py

from .featureX import FeatureX

def test_feature_x_behavior():
    fx = FeatureX()
    assert fx.do_something() == 'expected result'
```

## Commands
| Command        | Purpose                                      |
|----------------|----------------------------------------------|
| /add-module    | Scaffold and add a new module                |
| /run-tests     | Run all test files matching *.test.* pattern |
```
