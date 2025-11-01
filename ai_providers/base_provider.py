from abc import ABC, abstractmethod

class BaseAIProvider(ABC):
    """
    Abstract interface for all AI service providers.
    """

    @abstractmethod
    def initialize(self):
        """
        Initialize and configure the API connection (e.g., load API key or credentials).
        """
        pass

    @abstractmethod
    def verify(self, match_text: str) -> bool:
        """
        Send the given string to the AI model for verification.
        Must return True if it's a secret, or False if it's safe.
        """
        pass
