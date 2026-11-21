#!/usr/bin/env python3
"""Single-import entrypoint: preserve the FD-owner ContextVar across lab modules."""
from gaslux_popos_six_gpt_ownership import main


if __name__ == "__main__":
    raise SystemExit(main())
