"""
Finite field arithmetic for Shamir's Secret Sharing
Using GF(2^8) for byte-oriented operations
"""

import secrets


class GF256:
    """
    Galois Field GF(2^8) implementation for Shamir's Secret Sharing
    Uses irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
    """

    # Precomputed tables for efficiency. Populated once by
    # ``_initialize_tables`` (guarded by ``_initialized``) before any lookup;
    # the empty lists are placeholders that are never indexed pre-init.
    _exp_table: list[int] = []
    _log_table: list[int] = []
    _initialized = False

    @classmethod
    def _initialize_tables(cls) -> None:
        """Initialize exponential and logarithm tables"""
        if cls._initialized:
            return

        cls._exp_table = [0] * 512
        cls._log_table = [0] * 256

        # Generate exponential table
        x = 1
        for i in range(255):
            cls._exp_table[i] = x
            cls._log_table[x] = i
            x = cls._multiply_raw(x, 3)  # 3 is a primitive element

        # Handle overflow
        for i in range(255, 512):
            cls._exp_table[i] = cls._exp_table[i - 255]

        cls._log_table[0] = 0  # Special case
        cls._initialized = True

    @classmethod
    def _multiply_raw(cls, a: int, b: int) -> int:
        """Raw multiplication without table lookup"""
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b  # Irreducible polynomial
            b >>= 1
        return result & 0xff

    @classmethod
    def add(cls, a: int, b: int) -> int:
        """Addition in GF(2^8) (XOR)"""
        return a ^ b

    @classmethod
    def subtract(cls, a: int, b: int) -> int:
        """Subtraction in GF(2^8) (same as addition)"""
        return a ^ b

    @classmethod
    def multiply(cls, a: int, b: int) -> int:
        """Multiplication in GF(2^8)"""
        cls._initialize_tables()

        if a == 0 or b == 0:
            return 0

        return cls._exp_table[cls._log_table[a] + cls._log_table[b]]

    @classmethod
    def divide(cls, a: int, b: int) -> int:
        """Division in GF(2^8)"""
        if b == 0:
            raise ZeroDivisionError("Division by zero in GF(2^8)")

        if a == 0:
            return 0

        cls._initialize_tables()
        return cls._exp_table[cls._log_table[a] - cls._log_table[b] + 255]

    @classmethod
    def power(cls, a: int, exp: int) -> int:
        """Exponentiation in GF(2^8)"""
        if exp == 0:
            return 1
        if a == 0:
            return 0

        cls._initialize_tables()
        return cls._exp_table[(cls._log_table[a] * exp) % 255]

    @classmethod
    def inverse(cls, a: int) -> int:
        """Multiplicative inverse in GF(2^8)"""
        if a == 0:
            raise ZeroDivisionError("Zero has no inverse in GF(2^8)")

        cls._initialize_tables()
        return cls._exp_table[255 - cls._log_table[a]]


class ShamirSecretSharing:
    """
    Proper Shamir's Secret Sharing implementation using finite field arithmetic
    """

    def __init__(self, threshold: int, total_shares: int):
        """
        Initialize Shamir's Secret Sharing

        Args:
            threshold: Minimum number of shares needed to reconstruct
            total_shares: Total number of shares to create
        """
        if isinstance(threshold, bool) or isinstance(total_shares, bool) or \
                not isinstance(threshold, int) or not isinstance(total_shares, int):
            raise ValueError("Threshold and total shares must be integers")
        if threshold <= 0:
            raise ValueError("Threshold must be positive")
        if threshold > total_shares:
            raise ValueError("Threshold cannot exceed total shares")
        if total_shares > 255:
            raise ValueError("Total shares cannot exceed 255")

        self.threshold = threshold
        self.total_shares = total_shares

    def split_secret(self, secret: bytes) -> list[tuple[int, bytes]]:
        """
        Split secret into shares

        Args:
            secret: Secret bytes to split

        Returns:
            List of (x, share_bytes) tuples
        """
        # Generate one polynomial per secret byte and reuse it for every share.
        # Re-rolling coefficients per share makes reconstruction impossible.
        polynomials = []
        for secret_byte in secret:
            coefficients = [secret_byte]
            for _ in range(1, self.threshold):
                # CSPRNG (secrets/os.urandom), never the non-cryptographic
                # `random` module. Shamir secrecy depends on unpredictable
                # coefficients. secrets is fail-closed (raises if no OS entropy
                # source). Audit: CITRATE_SDK_PYTHON-2026-05-31-002.
                coefficients.append(secrets.randbelow(256))
            polynomials.append(coefficients)

        shares = []
        for i in range(1, self.total_shares + 1):
            share_bytes = self._evaluate_polynomial_at_point(polynomials, i)
            shares.append((i, share_bytes))

        return shares

    @staticmethod
    def validate_shares(shares: list[tuple[int, bytes]]) -> None:
        """Validate a share set before any interpolation (PBA-L4-005 variant).

        Every share, not only the first ``threshold``, must have an integer x in
        1..255 (x = 0 is the secret itself: a share there dictates the output),
        x values must be distinct, and every y must be non-empty bytes of one
        common length. Raises ValueError on the first violation.
        """
        if not shares:
            raise ValueError("No shares provided")
        seen: set[int] = set()
        length: int | None = None
        for share in shares:
            if not isinstance(share, tuple) or len(share) != 2:
                raise ValueError("Invalid share: expected an (x, y) tuple")
            x, y = share
            if isinstance(x, bool) or not isinstance(x, int) or x < 1 or x > 255:
                raise ValueError(f"Invalid share: x must be an integer in 1..255, got {x!r}")
            if x in seen:
                raise ValueError(f"Invalid share set: duplicate share x = {x}")
            seen.add(x)
            if not isinstance(y, (bytes, bytearray)):
                raise ValueError("Invalid share: y must be bytes")
            if length is None:
                length = len(y)
            elif len(y) != length:
                raise ValueError("Invalid share set: all shares must have the same length")
        if not length:
            raise ValueError("Invalid share set: share y is empty")

    def reconstruct_secret(self, shares: list[tuple[int, bytes]]) -> bytes:
        """
        Reconstruct secret from shares

        Args:
            shares: List of (x, share_bytes) tuples

        Returns:
            Reconstructed secret bytes
        """
        self.validate_shares(shares)
        if len(shares) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} shares, got {len(shares)}")

        # Use first threshold shares
        active_shares = shares[:self.threshold]
        share_length = len(active_shares[0][1])

        secret_bytes = []
        for byte_pos in range(share_length):
            points = [(x, share_bytes[byte_pos]) for x, share_bytes in active_shares]
            # Lagrange interpolation at x = 0
            secret_bytes.append(self._lagrange_interpolation(points, 0))

        return bytes(secret_bytes)

    def _evaluate_polynomial_at_point(self, polynomials: list[list[int]], x: int) -> bytes:
        """
        Evaluate polynomial at point x for each byte of the secret
        """
        share_bytes = []

        for coefficients in polynomials:
            # Evaluate polynomial at x
            result = 0
            x_power = 1

            for coeff in coefficients:
                result = GF256.add(result, GF256.multiply(coeff, x_power))
                x_power = GF256.multiply(x_power, x)

            share_bytes.append(result)

        return bytes(share_bytes)

    def _lagrange_interpolation(self, points: list[tuple[int, int]], x: int) -> int:
        """
        Lagrange interpolation: f(x) from the given points.

        Callers validate first (``validate_shares``): x values are distinct
        integers in 1..255, so every denominator is nonzero; ``GF256.divide``
        still raises on a zero divisor as a backstop.
        """
        result = 0
        for i, (x_i, y_i) in enumerate(points):
            numerator = 1
            denominator = 1
            for j, (x_j, _) in enumerate(points):
                if i == j:
                    continue
                # (x - x_j) = x XOR x_j in GF(2^8); at x = 0 this is x_j.
                numerator = GF256.multiply(numerator, GF256.subtract(x, x_j))
                denominator = GF256.multiply(denominator, GF256.subtract(x_i, x_j))
            result = GF256.add(result, GF256.multiply(y_i, GF256.divide(numerator, denominator)))
        return result

    def verify_shares(self, shares: list[tuple[int, bytes]]) -> bool:
        """
        Check that a share set is structurally valid and CONSISTENT: every share
        beyond the first ``threshold`` must lie on the polynomial those first
        ``threshold`` shares define (PBA-L4-005 variant; the old version only
        checked that interpolation did not raise).

        With exactly ``threshold`` shares there is no redundancy, so any
        structurally valid set is consistent by definition and a forged share
        cannot be detected. Use verifiable secret sharing when that matters.
        """
        try:
            self.validate_shares(shares)
        except ValueError:
            return False
        if len(shares) < self.threshold:
            return False
        base = shares[:self.threshold]
        for x_extra, y_extra in shares[self.threshold:]:
            for b, expected in enumerate(y_extra):
                points = [(x, y[b]) for x, y in base]
                if self._lagrange_interpolation(points, x_extra) != expected:
                    return False
        return True


def split_secret_bytes(secret: bytes, threshold: int, total_shares: int) -> list[tuple[int, bytes]]:
    """
    Convenience function to split secret bytes

    Args:
        secret: Secret bytes to split
        threshold: Minimum shares needed to reconstruct
        total_shares: Total number of shares to create

    Returns:
        List of (share_id, share_bytes) tuples
    """
    sss = ShamirSecretSharing(threshold, total_shares)
    return sss.split_secret(secret)


def reconstruct_secret_bytes(shares: list[tuple[int, bytes]], threshold: int) -> bytes:
    """
    Convenience function to reconstruct secret bytes

    Args:
        shares: List of (share_id, share_bytes) tuples
        threshold: Minimum shares needed

    Returns:
        Reconstructed secret bytes
    """
    # Infer total_shares from the shares provided
    total_shares = max(len(shares), threshold)
    sss = ShamirSecretSharing(threshold, total_shares)
    return sss.reconstruct_secret(shares)
