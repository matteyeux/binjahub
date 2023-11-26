import os
import secrets
from ldap3 import SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPPasswordIsMandatoryError
from ldap3.utils.conv import escape_filter_chars


internal_ldap_args = {}
internal_jwt_secret = ""


def setup_ldap_auth(**kwargs):
    global internal_jwt_secret
    global internal_ldap_args
    internal_ldap_args = kwargs
    internal_jwt_secret = os.getenv("JWT_SECRET", secrets.token_urlsafe(64))


def jwt_secret():
    return internal_jwt_secret


def uses_auth():
    if internal_ldap_args["url"]:
        return True
    return False


def convert_user_to_dn(user: str):
    if "@" not in user:
        return user
    user, domain = user.split("@", 1)
    domain = domain.split(".")
    return f"cn={user},dc={',dc='.join(domain)}"


def ldap_connect(user="", password=""):
    try:
        s = Server(internal_ldap_args["url"], get_info="ALL")
        conn = Connection(
            s,
            user=convert_user_to_dn(internal_ldap_args["user"]),
            password=internal_ldap_args["password"],
        )
        if conn.bind():
            if user and password:
                user = escape_filter_chars(user)
                conn.search(
                    search_base=internal_ldap_args["base"],
                    search_filter=f"(uid={user})",
                    search_scope=SUBTREE,
                    attributes=[],
                )
                if not conn.entries:
                    conn.unbind()
                    return False
                dn = conn.entries[0].entry_dn
                if not conn.rebind(user=dn, password=password):
                    return False
                # authenticated
                conn.unbind()
                return True
            else:
                conn.unbind()
                return True
        return False

    except (LDAPBindError, LDAPPasswordIsMandatoryError):
        return False
