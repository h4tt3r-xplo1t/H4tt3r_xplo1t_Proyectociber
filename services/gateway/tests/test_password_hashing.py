from gateway.passwords import hash_password, verify_password

SAMPLE = "a sample passphrase for tests"  # noqa: S105  (fake, not a real secret)


def test_hash_uses_argon2id_with_adr_parameters():
    hashed = hash_password(SAMPLE)

    assert hashed.startswith("$argon2id$")
    assert "m=19456,t=2,p=1" in hashed


def test_verify_accepts_right_and_rejects_wrong_password():
    hashed = hash_password(SAMPLE)

    assert verify_password(hashed, SAMPLE) is True
    assert verify_password(hashed, SAMPLE + "x") is False
