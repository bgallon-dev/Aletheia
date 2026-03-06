from aletheia.store.verify import VerificationResult


def _passing_result() -> VerificationResult:
    result = VerificationResult()
    result.cryptographic_match = True
    result.forensic_match = True
    return result


def test_present_invalid_signature_fails():
    result = _passing_result()
    result.signature_present = True
    result.signature_valid = False
    assert result.passed() is False


def test_require_signature_missing_fails():
    result = _passing_result()
    result.signature_required = True
    result.signature_present = False
    assert result.passed() is False


def test_require_signature_valid_passes():
    result = _passing_result()
    result.signature_required = True
    result.signature_present = True
    result.signature_valid = True
    assert result.passed() is True
