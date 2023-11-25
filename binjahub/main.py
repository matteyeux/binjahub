#!/usr/bin/env python3
"""Main code for the oracle API."""
import argparse
from getpass import getpass
import uvicorn

from binjahub.auth import setup_ldap_auth
from dotenv import load_dotenv


def parse_arguments() -> argparse.Namespace:
    """Parse arguments from cmdline to initialize
    optional settings such as port or reload.
    """
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        dest="host",
        default="127.0.0.1",
        help="specify host",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        dest="port",
        default=5555,
        help="specify port",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="debug mode",
    )
    parser.add_argument(
        "-r",
        "--reload",
        action="store_true",
        default=False,
        help="autoreload",
    )
    parser.add_argument("-s", "--server", default=None, help="LDAP server URL")
    parser.add_argument(
        "-b", "--base-dn", default=None, help="LDAP base DN to search for users"
    )
    parser.add_argument("-u", "--bind-user", default=None, help="LDAP Bind username")
    parser.add_argument(
        "-P", "--bind-password", default=None, help="LDAP Bind password"
    )
    return parser.parse_args()


def main() -> int:
    """Main function which will run the uvicorn
    web server and run the API from app.py."""
    parser = parse_arguments()
    password = parser.bind_password
    if parser.bind_user and not password:
        password = getpass(f"{parser.bind_user} password: ")

    setup_ldap_auth(
        url=parser.server,
        base=parser.base_dn,
        user=parser.bind_user,
        password=parser.bind_password,
    )

    uvicorn.run(
        "binjahub.app:app",
        host=parser.host,
        port=parser.port,
        reload=parser.reload,
    )

    return 0


if __name__ == "__main__":
    main()
