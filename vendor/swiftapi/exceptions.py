"""
SwiftAPI SDK Exceptions
"""


class SwiftAPIError(Exception):
    """Base exception for SwiftAPI SDK errors."""

    def __init__(self, message: str, status_code: int = None, response: dict = None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


class AuthenticationError(SwiftAPIError):
    """Raised when API key is invalid or missing."""
    pass


class PolicyViolation(SwiftAPIError):
    """Raised when an action violates policy and is denied."""

    def __init__(self, message: str, action_type: str = None, denial_reason: str = None):
        self.action_type = action_type
        self.denial_reason = denial_reason
        super().__init__(message)


class SignatureVerificationError(SwiftAPIError):
    """Raised when attestation signature verification fails."""
    pass


class AttestationExpiredError(SwiftAPIError):
    """Raised when an attestation has expired."""
    pass


class AttestationRevokedError(SwiftAPIError):
    """Raised when an attestation has been revoked."""

    def __init__(self, jti: str):
        self.jti = jti
        super().__init__(f"Attestation {jti} has been revoked")


class RateLimitError(SwiftAPIError):
    """Raised when rate limit is exceeded."""

    def __init__(self, retry_after: int = None):
        self.retry_after = retry_after
        message = "Rate limit exceeded"
        if retry_after:
            message += f", retry after {retry_after}s"
        super().__init__(message)


class NetworkError(SwiftAPIError):
    """Raised when network connectivity fails."""
    pass
