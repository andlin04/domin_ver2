from domin import totp


def test_code_matches_across_the_window_and_is_six_digits():
    secret = totp.new_secret()
    now = 1_700_000_000.0
    step = int(now // totp.STEP)
    code = totp._code(secret, step)
    assert len(code) == totp.DIGITS and code.isdigit()
    # the current, previous and next step are accepted (clock drift)
    assert totp.verify(secret, code, now=now) == step
    assert totp.verify(secret, totp._code(secret, step - 1), now=now) == step - 1
    assert totp.verify(secret, totp._code(secret, step + 1), now=now) == step + 1


def test_a_code_cannot_be_replayed():
    secret = totp.new_secret()
    now = 1_700_000_000.0
    step = totp.verify(secret, totp._code(secret, int(now // totp.STEP)), now=now)
    assert step is not None
    # once last_step has advanced to this step, the same code is refused
    assert totp.verify(secret, totp._code(secret, step), last_step=step, now=now) is None


def test_bad_input_is_rejected():
    secret = totp.new_secret()
    assert totp.verify(secret, "") is None
    assert totp.verify(secret, "12345") is None       # wrong length
    assert totp.verify(secret, "abcdef") is None       # not digits
    assert totp.verify(secret, "000000", now=0) in (None, 0)   # almost certainly wrong


def test_recovery_codes_hash_stably_and_are_unique():
    codes = totp.new_recovery_codes(8)
    assert len(codes) == 8 and len(set(codes)) == 8
    assert totp.hash_recovery(codes[0]) == totp.hash_recovery(codes[0].upper() + " ")
    assert totp.hash_recovery(codes[0]) != totp.hash_recovery(codes[1])


def test_provisioning_uri_carries_the_secret_and_issuer():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "admin")
    assert uri.startswith("otpauth://totp/") and "secret=JBSWY3DPEHPK3PXP" in uri and "issuer=domin" in uri
