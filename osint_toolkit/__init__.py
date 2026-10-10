"""Passive OSINT toolkit."""

from .ai import generate_ai_briefing, get_available_models, is_ollama_available
from .core import DomainValidationError, normalize_domain
from .services import (
    search_censys,
    search_ip2location,
    search_shodan,
    search_virustotal,
)
from .username import UsernameValidationError, search_username

__all__ = [
    "DomainValidationError",
    "UsernameValidationError",
    "generate_ai_briefing",
    "get_available_models",
    "is_ollama_available",
    "normalize_domain",
    "search_censys",
    "search_ip2location",
    "search_shodan",
    "search_username",
    "search_virustotal",
]
__version__ = "0.1.0"


