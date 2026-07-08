# promptshield-llm

[![PyPI](https://img.shields.io/badge/PyPI-promptshield--llm-blue.svg)](https://pypi.org/project/promptshield-llm/)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-brightgreen.svg)](https://www.mozilla.org/en-US/MPL/2.0/)

Redact sensitive data from LLM prompts before sending them to a model.

## Installation

```bash
pip install promptshield-llm
```

## Usage

```python
from promptshield import shield_prompt

prompt = "Summarize this email from eduardo@example.com. Token: Bearer abc123456789"
safe_prompt = shield_prompt(prompt)

print(safe_prompt)
```

## Output

```txt
Summarize this email from [EMAIL]. Token: [TOKEN]
```

## Find sensitive data

```python
from promptshield import find_sensitive

matches = find_sensitive("Contact me at eduardo@example.com")
print(matches)
```

## Custom patterns

```python
from promptshield import shield_prompt

safe = shield_prompt(
    "Customer ID: CUST-12345",
    custom_patterns={"customer_id": r"CUST-\d+"}
)

print(safe)
```

## Overview

`promptshield-llm` is a tiny Python utility for masking sensitive values in prompts, logs, and LLM inputs.

It is useful when building:
- LLM applications
- RAG pipelines
- AI agents
- prompt logging systems
- internal AI tools

## Features

- Redacts emails
- Redacts phone numbers
- Redacts API keys and tokens
- Redacts sensitive URLs
- Supports custom regex patterns
- Uses the Python standard library
- Simple API

## Limitations

`promptshield-llm` is regex-based and may not catch every possible secret or personal identifier. Use it as an extra safety layer, not as your only security control.

## Issues

Report issues at:
https://github.com/edujbarrios/promptshield-llm

## Author

Eduardo J. Barrios
edujbarrios@outlook.com

## License

Mozilla Public License 2.0
