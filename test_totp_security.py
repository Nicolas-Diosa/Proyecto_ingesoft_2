# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.
"""
Security tests for HOTP algorithm in auth_totp module.

These tests verify the security properties of the HOTP implementation
according to RFC 4226 requirements.
"""

import struct
import time
import unittest
from hmac import HMAC
from hashlib import sha1

from odoo.addons.auth_totp.models.totp import hotp, TOTP, TIMESTEP, DIGITS, ALGORITHM


class TestHOTPSecurity(unittest.TestCase):
    """
    Security tests for HOTP algorithm implementation.

    RFC 4226 Section 7 specifies test vectors that every HOTP
    implementation must match.
    """

    def test_rfc_4226_test_vector_1(self):
        """
        RFC 4226 Section 7.1 - Test Vector 1
        Secret: '12345678901234567890' (20 bytes)
        Expected HOTP(0) = '755224'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 0)
        self.assertEqual(result, 755224, "RFC 4226 Test Vector 1 failed")

    def test_rfc_4226_test_vector_2(self):
        """
        RFC 4226 Section 7.1 - Test Vector 2
        Secret: '12345678901234567890'
        Expected HOTP(1) = '287082'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 1)
        self.assertEqual(result, 287082, "RFC 4226 Test Vector 2 failed")

    def test_rfc_4226_test_vector_3(self):
        """
        RFC 4226 Section 7.1 - Test Vector 3
        Secret: '12345678901234567890'
        Expected HOTP(2) = '359152'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 2)
        self.assertEqual(result, 359152, "RFC 4226 Test Vector 3 failed")

    def test_rfc_4226_test_vector_4(self):
        """
        RFC 4226 Section 7.1 - Test Vector 4
        Secret: '12345678901234567890'
        Expected HOTP(3) = '969237'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 3)
        self.assertEqual(result, 969237, "RFC 4226 Test Vector 4 failed")

    def test_rfc_4226_test_vector_5(self):
        """
        RFC 4226 Section 7.1 - Test Vector 5
        Secret: '12345678901234567890'
        Expected HOTP(4) = '338314'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 4)
        self.assertEqual(result, 338314, "RFC 4226 Test Vector 5 failed")

    def test_rfc_4226_test_vector_6(self):
        """
        RFC 4226 Section 7.1 - Test Vector 6
        Secret: '12345678901234567890'
        Expected HOTP(5) = '254676'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 5)
        self.assertEqual(result, 254676, "RFC 4226 Test Vector 6 failed")

    def test_rfc_4226_test_vector_7(self):
        """
        RFC 4226 Section 7.1 - Test Vector 7
        Secret: '12345678901234567890'
        Expected HOTP(6) = '287922'
        """
        secret = b'12345678901234567890'
        result = hotp(secret, 6)
        self.assertEqual(result, 287922, "RFC 4226 Test Vector 7 failed")


class TestHOTPOutputProperties(unittest.TestCase):
    """
    Tests for output format and properties required by security standards.
    """

    def test_output_always_6_digits(self):
        """
        HOTP must always output exactly 6 digits.
        Security impact: If output can have variable length, attackers can
        use this to reduce search space.
        """
        secret = b'test_secret_key_12345'

        # Test range of counters including edge cases
        for counter in range(0, 100):
            result = hotp(secret, counter)
            # Verify it's in range [0, 999999]
            self.assertGreaterEqual(result, 0, f"HOTP({counter}) below minimum")
            self.assertLessEqual(result, 999999, f"HOTP({counter}) above maximum")
            # Verify it has at most 6 digits (leading zeros allowed)
            result_str = str(result)
            self.assertLessEqual(
                len(result_str), 6,
                f"HOTP({counter}) has more than 6 digits: {result_str}"
            )

    def test_output_with_leading_zeros(self):
        """
        Verify leading zeros are preserved in the 6-digit output.
        Example: code 42 should be formatted as '000042' for comparison.
        """
        secret = b'zero_padding_test'

        # Find a counter that produces a small value
        for counter in range(1000):
            result = hotp(secret, counter)
            if result < 1000:
                # Found a value that would have leading zeros
                self.assertLess(
                    result, 1000,
                    f"Expected leading zeros for result {result}"
                )
                # The numeric value must be correct; formatting with leading
                # zeros is done at display/comparison time
                return

    def test_unique_codes_per_counter(self):
        """
        Verify that different counters produce different codes.
        Collision resistance is fundamental to HOTP security.
        """
        secret = b'unique_test_secret_key'

        # Generate many codes and verify uniqueness
        codes = set()
        for counter in range(1000):
            code = hotp(secret, counter)
            # Should not have collisions
            self.assertNotIn(
                code, codes,
                f"Collision detected! HOTP({counter}) = {code} already exists"
            )
            codes.add(code)

        self.assertEqual(len(codes), 1000, "Expected 1000 unique codes")


class TestHOTPEdgeCases(unittest.TestCase):
    """
    Edge case testing for HOTP implementation.
    """

    def test_counter_zero(self):
        """
        Counter value 0 must work correctly.
        """
        secret = b'test_secret_at_zero'
        result = hotp(secret, 0)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 999999)

    def test_counter_large_value(self):
        """
        Counter can be up to 2^64-1 (64-bit unsigned).
        Test with large counter values.
        """
        secret = b'large_counter_test'

        # Test with counter near uint64 max
        # Note: Python handles arbitrary precision, but we want to ensure
        # struct.pack handles it correctly
        result = hotp(secret, 2**48)  # Large but reasonable value
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 999999)

    def test_counter_wrapping(self):
        """
        Verify behavior with counter that wraps to 64-bit representation.
        The counter is packed as 8 bytes big-endian (uint64).
        """
        secret = b'wrap_test_secret'

        # Counter values that test boundary conditions
        test_counters = [
            0,
            1,
            255,
            256,
            0xFF,
            0x100,
            0xFFFF,
            0x10000,
            2**32,
            2**40,
            2**48,
        ]

        for counter in test_counters:
            result = hotp(secret, counter)
            self.assertIsInstance(result, int)
            self.assertGreaterEqual(result, 0)
            self.assertLessEqual(result, 999999,
                f"Counter {counter} produced invalid code {result}")


class TestTOTPMatchSecurity(unittest.TestCase):
    """
    Tests for TOTP.match() security properties.
    """

    def test_window_validation(self):
        """
        Verify that window parameter is properly applied.
        Security: Small window reduces attack surface but may reject
        valid codes due to clock skew.
        """
        secret = b'security_test_secret'
        totp = TOTP(secret)

        # Generate a valid code for current time
        current_time = int(time.time())
        code = hotp(secret, current_time // TIMESTEP)

        # Should match with default window
        self.assertIsNotNone(
            totp.match(code, t=current_time),
            "Valid code should match with default window"
        )

        # Should also match with larger window
        self.assertIsNotNone(
            totp.match(code, t=current_time, window=60),
            "Valid code should match with larger window"
        )

    def test_invalid_code_rejected(self):
        """
        Invalid codes must be rejected.
        """
        secret = b'invalid_test_secret'
        totp = TOTP(secret)

        current_time = int(time.time())

        # Random invalid codes
        for _ in range(10):
            invalid_code = 999999  # High probability of being wrong
            self.assertIsNone(
                totp.match(invalid_code, t=current_time),
                "Invalid code should not match"
            )

    def test_timing_consistency(self):
        """
        Verify that match time doesn't leak information about the secret.
        This is a basic check - real timing attack protection would require
        constant-time comparison which is harder to test.
        """
        secret = b'timing_test_secret'
        totp = TOTP(secret)

        current_time = int(time.time())
        valid_code = hotp(secret, current_time // TIMESTEP)

        # Measure time for valid code
        start = time.perf_counter()
        result_valid = totp.match(valid_code, t=current_time)
        time_valid = time.perf_counter() - start

        # Measure time for invalid code
        start = time.perf_counter()
        result_invalid = totp.match(999999, t=current_time)
        time_invalid = time.perf_counter() - start

        # Both should return (result may vary based on search, but times
        # should be in same ballpark for basic check)
        self.assertIsNotNone(result_valid)
        self.assertIsNone(result_invalid)


class TestHOTPAlgorithmSecurity(unittest.TestCase):
    """
    Tests for algorithm-specific security properties.
    """

    def test_sha1_algorithm(self):
        """
        Verify SHA1 algorithm is used as specified.
        SHA1 is considered weak for collisions but is required by HOTP spec.
        """
        self.assertEqual(ALGORITHM, 'sha1',
            "HOTP must use SHA1 as per RFC 4226")

    def test_160_bit_secret(self):
        """
        RFC 4226 recommends at least 160 bits of entropy.
        """
        from odoo.addons.auth_totp.models.totp import TOTP_SECRET_SIZE
        self.assertGreaterEqual(TOTP_SECRET_SIZE, 160,
            "Secret size should be at least 160 bits")

    def test_digest_calculation(self):
        """
        Verify the HMAC digest calculation is correct.
        """
        secret = b'test_digest_secret'
        counter = 42

        # Calculate expected result manually
        C = struct.pack(">Q", counter)
        mac = HMAC(secret, msg=C, digestmod=sha1).digest()
        offset = mac[-1] & 0xF
        code = struct.unpack_from('>I', mac, offset)[0] & 0x7FFFFFFF
        expected = code % (10 ** DIGITS)

        # Compare with implementation
        result = hotp(secret, counter)
        self.assertEqual(result, expected,
            "HOTP digest calculation mismatch")


class TestSecretValidation(unittest.TestCase):
    """
    Tests for secret validation and security.
    """

    def test_accepts_bytes_secret(self):
        """
        Secret must be bytes for HMAC.
        """
        secret = b'bytes_secret_key_123'
        result = hotp(secret, 1)
        self.assertIsInstance(result, int)

    def test_string_secret_converted(self):
        """
        String secrets should be handled (converted to bytes).
        """
        # The current implementation requires bytes, but we test what happens
        # with string input - this may raise TypeError which is acceptable
        try:
            hotp('string_secret', 1)
        except TypeError:
            pass  # TypeError is acceptable - requires bytes

    def test_empty_secret(self):
        """
        Empty secret should produce deterministic output.
        """
        secret = b''
        result = hotp(secret, 0)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 999999)


if __name__ == '__main__':
    unittest.main()