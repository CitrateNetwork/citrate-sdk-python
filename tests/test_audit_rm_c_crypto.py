"""RM-C sdk-python crypto tripwires — inaugural federation deep audit.

Guards CITRATE_SDK_PYTHON-2026-05-31-002 (CSPRNG Shamir coefficients). These
assert behavior the pre-fix code violated; they are red on the old code
(non-cryptographic ``random.randint``) and green on the fix.
"""
import citrate_sdk.finite_field as ff
from citrate_sdk.finite_field import ShamirSecretSharing


def test_finite_field_uses_csprng_not_random():
    # The secrets CSPRNG is the entropy source; the non-cryptographic `random`
    # module is no longer imported into the finite-field module.
    assert hasattr(ff, "secrets"), "finite_field must use the secrets CSPRNG"
    assert not hasattr(ff, "random"), "finite_field must not import the weak random module"


def test_shamir_round_trip_any_threshold_subset():
    sss = ShamirSecretSharing(3, 5)
    secret = bytes([1, 2, 3, 0, 255, 128, 7])
    shares = sss.split_secret(secret)
    assert len(shares) == 5
    # First threshold shares reconstruct.
    assert bytes(sss.reconstruct_secret(shares[:3])) == secret
    # A disjoint subset of threshold shares also reconstructs (true t-of-n).
    assert bytes(sss.reconstruct_secret([shares[1], shares[3], shares[4]])) == secret


def test_shamir_coefficients_are_nondeterministic():
    sss = ShamirSecretSharing(3, 5)
    a = sss.split_secret(b"hello-world")
    b = sss.split_secret(b"hello-world")
    # Same secret, fresh CSPRNG coefficients each split -> different shares.
    assert bytes(a[0][1]) != bytes(b[0][1])
