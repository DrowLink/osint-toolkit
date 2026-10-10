"""Passive OSINT toolkit."""

from .core import DomainValidationError, normalize_domain
from .username import UsernameValidationError, search_username

__all__ = [
    "DomainValidationError",
    "UsernameValidationError",
    "normalize_domain",
    "search_username",
]
__version__ = "0.1.0"
