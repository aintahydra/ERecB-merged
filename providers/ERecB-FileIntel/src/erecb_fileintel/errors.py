class FileIntelError(Exception):
    """Base exception for application errors."""


class ConfigError(FileIntelError):
    """Invalid runtime configuration."""


class DatabaseError(FileIntelError):
    """Database operation failed."""


class FatalScanError(FileIntelError):
    """A scan cannot continue."""


class RecoverableScanError(FileIntelError):
    def __init__(self, phase: str, error_type: str, message: str) -> None:
        super().__init__(message)
        self.phase = phase
        self.type = error_type
        self.message = message


class ProviderError(FileIntelError):
    def __init__(self, status: str, message: str, http_status: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.http_status = http_status


class ProviderAuthError(ProviderError):
    def __init__(self, message: str, http_status: int | None = None) -> None:
        super().__init__("auth_error", message, http_status)


class ProviderRateLimitError(ProviderError):
    def __init__(self, message: str, http_status: int | None = None) -> None:
        super().__init__("rate_limited", message, http_status)

