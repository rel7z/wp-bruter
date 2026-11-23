#!/usr/bin/env python3
"""Offline tests for verify_creds (no network).

Run: python3 -m unittest tools.test_verify_creds   (from repo root, needs
tools/ on sys.path) or just  python3 tools/test_verify_creds.py
"""

from __future__ import annotations

import http.cookiejar
import os
import sys
import time
import unittest
from email.message import Message

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import verify_creds as V  # noqa: E402


def headers(*set_cookies: str) -> Message:
    msg = Message()
    for value in set_cookies:
        msg["Set-Cookie"] = value
    return msg


class ParseLine(unittest.TestCase):
    def test_pipe(self):
        c = V.parse_line("example.com | admin | hunter2")
        self.assertEqual((c.site, c.user, c.password), ("https://example.com", "admin", "hunter2"))

    def test_scheme_kept_and_trailing_slash_stripped(self):
        c = V.parse_line("http://example.com/ | a | b")
        self.assertEqual(c.site, "http://example.com")

    def test_pipe_in_password(self):
        c = V.parse_line("example.com | a | p|w")
        self.assertEqual(c.password, "p|w")

    def test_tab_and_comma(self):
        self.assertEqual(V.parse_line("s\tu\tp").user, "u")
        self.assertEqual(V.parse_line("s,u,p").password, "p")

    def test_comment_and_short(self):
        self.assertIsNone(V.parse_line("# x"))
        self.assertIsNone(V.parse_line("only | two"))


class LiveAuthCookie(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(V.live_auth_cookie(headers("wordpress_logged_in_abc=u%7C1%7Cx; path=/")))

    def test_empty_plus_deleted(self):
        for value in ("", "+", "deleted"):
            self.assertFalse(V.live_auth_cookie(headers(f"wordpress_logged_in_abc={value}; path=/")))

    def test_max_age_zero(self):
        self.assertFalse(
            V.live_auth_cookie(headers("wordpress_logged_in_abc=v; path=/; Max-Age=0"))
        )

    def test_past_expires(self):
        self.assertFalse(
            V.live_auth_cookie(
                headers("wordpress_logged_in_abc=v; Expires=Wed, 11 Jan 1984 05:00:00 GMT")
            )
        )

    def test_future_expires_ok(self):
        future = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 3600))
        self.assertTrue(V.live_auth_cookie(headers(f"wordpress_logged_in_abc=v; Expires={future}")))

    def test_unrelated_cookie_ignored(self):
        self.assertFalse(V.live_auth_cookie(headers("wordpress_test_cookie=WP+Cookie+check")))

    def test_picks_live_among_many(self):
        msg = headers(
            "wordpress_logged_in_abc=; path=/",
            "wordpress_logged_in_def=value; path=/",
        )
        self.assertTrue(V.live_auth_cookie(msg))


class JarLiveAuth(unittest.TestCase):
    @staticmethod
    def make(name, value, expires=None):
        return http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain="example.com", domain_specified=False, domain_initial_dot=False,
            path="/", path_specified=True, secure=True, expires=expires,
            discard=False, comment=None, comment_url=None, rest={},
        )

    def test_session_cookie_is_live(self):
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(self.make("wordpress_logged_in_abc", "v"))
        self.assertTrue(V.jar_has_live_auth(jar))

    def test_expired_is_not(self):
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(self.make("wordpress_logged_in_abc", "v", expires=time.time() - 10))
        self.assertFalse(V.jar_has_live_auth(jar))

    def test_empty_jar(self):
        self.assertFalse(V.jar_has_live_auth(http.cookiejar.CookieJar()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
