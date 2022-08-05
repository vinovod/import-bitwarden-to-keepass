from enum import IntEnum
from urllib.parse import urlsplit, parse_qsl
import re


class Types(IntEnum):
    LOGIN = 1
    SECURE_NOTE = 2
    CARD = 3
    IDENTITY = 4


def prepare_key(v):
    reserved_keys = [
        "Title",
        "UserName",
        "Password",
        "URL",
        "Tags",
        "IconID",
        "Times",
        "History",
        "Notes",
        "otp",
    ]

    key = " ".join(
        w.title()
        for w in re.sub("([a-z])([A-Z])", r"\1 \2", v)
        .replace("-", " ")
        .replace("_", " ")
        .strip()
        .lower()
        .split(" ")
    )

    if key in reserved_keys:
        key = "{key} ".format(key=key)

    return key


class Item:
    def __init__(self, item):
        self.item = item

    def get_id(self) -> str:
        return self.item["id"]

    def get_name(self) -> str:
        return re.sub('(\\"|")', "", self.item["name"])

    def get_folder_id(self) -> str:
        return self.item["folderId"]

    def get_username(self) -> str:
        if "login" in self.item and self.item["login"]["username"]:
            return self.item["login"]["username"]
        if "identity" in self.item and self.item["identity"]["username"]:
            return self.item["identity"]["username"]
        else:
            return ""

    def get_password(self) -> str:
        if "login" not in self.item:
            return ""

        return self.item["login"]["password"] if self.item["login"]["password"] else ""

    def get_card_holder(self) -> str:
        if "card" not in self.item:
            return ""

        return (
            self.item["card"]["cardholderName"].strip()
            if self.item["card"]["cardholderName"]
            else ""
        )

    def get_card_brand(self) -> str:
        if "card" not in self.item:
            return ""

        return self.item["card"]["brand"].lower() if self.item["card"]["brand"] else ""

    def get_card_code(self) -> str:
        if "card" not in self.item:
            return ""

        return self.item["card"]["code"].strip() if self.item["card"]["code"] else ""

    def get_card_number(self) -> str:
        if "card" not in self.item:
            return ""

        return (
            self.item["card"]["number"].strip() if self.item["card"]["number"] else ""
        )

    def get_card_expiry(self) -> str:
        if "card" not in self.item:
            return ""

        return (
            "{month}/{year}".format(
                month=self.item["card"]["expMonth"].strip().zfill(2),
                year=self.item["card"]["expYear"].strip(),
            )
            if self.item["card"]["expMonth"] and self.item["card"]["expMonth"]
            else ""
        )

    def get_notes(self):
        return self.item["notes"]

    def get_uris(self):
        if "login" not in self.item or "uris" not in self.item["login"]:
            return []

        for uri in self.item["login"]["uris"]:
            uri["uri"] = uri["uri"] if uri["uri"] is not None else ""

        return self.item["login"]["uris"]

    def get_uri(self):
        uri = ""

        for u in self.get_uris():
            uri = u
            break

        return uri

    def get_custom_fields(self):
        results = []

        if "fields" not in self.item:
            return results

        for field in self.item["fields"]:
            name = prepare_key(field["name"]) if field["name"] is not None else ""

            field["name"] = name
            field["value"] = (
                field["value"].strip() if field["value"] is not None else ""
            )
            field["protected"] = field["type"] == 1

            if field["value"] in ["✓", "", " "]:
                continue

            results.append(field)

        return results

    def get_fields(self):
        sensitive = []
        regular = []

        for field in self.get_custom_fields():
            name = field["name"]
            is_sensitive = (
                bool(
                    re.search(
                        r"(phrase|code|2fa|totp|recovery|secret|security|passw)",
                        name,
                        re.IGNORECASE,
                    )
                )
                # or field["protected"]
            )

            if is_sensitive:
                sensitive.append(field)
            else:
                regular.append(field)

        return sensitive, regular

    def get_identity(self):
        identity = {}

        if "identity" not in self.item:
            return identity

        # ident = dict(self.item["identity"])

        for k, v in self.item["identity"].items():
            if k == "username":
                continue

            name = prepare_key(k)
            value = v if v is not None else ""

            identity[name] = value

        return identity

    def get_attachments(self):
        if "attachments" not in self.item:
            return []

        return self.item["attachments"]

    def get_totp(self):
        if "login" not in self.item:
            return None, None

        if not self.item["login"]["totp"]:
            return None, None

        params = urlsplit(self.item["login"]["totp"]).query
        params = dict(parse_qsl(params))
        period = params.get("period", 30)
        digits = params.get("digits", 6)
        secret = params.get("secret", self.item["login"]["totp"])

        return secret, f"{period};{digits}"
