"""Shared test helpers."""
import datetime

import jwt

TEST_ADMIN = 'admin'
TEST_PASSWORD = 'correct-horse-battery'


def access_token(main) -> str:
    """
    A valid access token for the admin account in the current (patched) test
    database, creating the account if needed.
    """
    from utils import auth

    admin = auth.get_admin()
    if not admin:
        auth.set_admin_password(TEST_ADMIN, TEST_PASSWORD)
        admin = auth.get_admin()
    return jwt.encode({
        'user': admin['username'],
        'type': 'access',
        'pv': admin['token_version'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
    }, main.JWT_SECRET, algorithm='HS256')
