import json
import logging
import os
import re
import subprocess
from datetime import date, timezone
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from argparse import ArgumentParser
from typing import Dict, List, Optional

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError
from pykeepass.group import Group as KPGroup

import folder as FolderType
from item import Item, Types as ItemTypes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s :: %(levelname)s :: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

kp: Optional[PyKeePass] = None
totp: Optional[PyKeePass] = None


def get_tag(t):
    if t == ItemTypes.CARD:
        return "card"
    elif t == ItemTypes.IDENTITY:
        return "identity"
    elif t == ItemTypes.SECURE_NOTE:
        return "note"
    else:
        return "login"


def attr(name=None, value=None, protected=True):
    return (
        {"name": name, "value": value, "protected": protected}
        if (name is not None) and (value is not None)
        else None
    )


def set_sensitive_attributes(entry, attrs):
    for attr in attrs:
        if attr is None:
            continue

        attr["protected"] = True

    set_attributes(entry, attrs)


def set_attributes(entry, attrs):
    for attr in attrs:
        if attr is None:
            continue

        entry.set_custom_property(
            attr["name"],
            attr["value"],
            protect=attr["protected"],
        )


def set_uris(entry, uris):
    attrs = []

    for i, uri in enumerate(uris):
        name = "KP2A_URL_{counter}".format(counter=i)

        if i == 0:
            entry.url = uri["uri"]
            name = "KP2A_URL"

        attrs.append(attr(name=name, value=uri["uri"], protected=False))

    set_attributes(entry, attrs)


def set_totp(entry, secret, settings):
    attrs = [
        attr(name="TOTP Seed", value=secret),
        attr(name="TOTP Settings", value=settings),
    ]

    set_attributes(entry, attrs)


def bitwarden2keepass(args):
    global kp, totp

    separated = bool(args.totp_db_path)

    try:
        kp = PyKeePass(
            args.db_path,
            password=args.db_password,
            keyfile=args.db_keyfile,
        )
    except FileNotFoundError:
        logging.info("KeePass db does not exist, creating a new one.")
        kp = create_database(
            args.db_path,
            password=args.db_password,
            keyfile=args.db_keyfile,
        )

        if separated:
            logging.info("KeePass TOTP db does not exist, creating a new one.")
            totp = create_database(
                args.totp_db_path,
                password=args.totp_db_password,
                keyfile=args.totp_db_keyfile,
            )
    except CredentialsError as e:
        logging.error(f"Wrong password for KeePass db: {e}")
        return

    folders = subprocess.check_output(
        [args.bw_path, "list", "folders", "--session", args.bw_session], encoding="utf8"
    )
    folders = json.loads(folders)
    groups_by_id = load_folders(folders)
    logging.info(f"Folders done ({len(groups_by_id)}).")

    items = subprocess.check_output(
        [args.bw_path, "list", "items", "--session", args.bw_session], encoding="utf8"
    )
    items = json.loads(items)

    logging.info(f"Starting to process {len(items)} items.")

    for item in items:
        bw_item = Item(item)
        is_duplicate_title = False
        item_type = item["type"]
        is_login = item_type == ItemTypes.LOGIN
        is_card = item_type == ItemTypes.CARD
        is_identity = item_type == ItemTypes.IDENTITY
        is_secure_note = item_type == ItemTypes.SECURE_NOTE

        default_tag = get_tag(item_type)

        totp_secret, totp_settings = bw_item.get_totp()
        totp_enabled = totp_secret or totp_settings
        sensitive, attrs = bw_item.get_fields()
        uris = bw_item.get_uris()
        notes = bw_item.get_notes()

        # Combine all fields from BW item,
        # if it's not a login item
        # or it's a single KeePass DB (TOTP stored with passswords)
        if not separated or not is_login:
            attrs = sensitive + attrs

        try:
            while True:
                entry_url = None
                entry_expiry_time = None
                entry_tags = [default_tag]
                entry_title = (
                    bw_item.get_name()
                    if not is_duplicate_title
                    else "{name} - {item_id}".format(
                        name=bw_item.get_name(), item_id=bw_item.get_id()
                    )
                )
                entry_username = (
                    bw_item.get_card_number() if is_card else bw_item.get_username()
                )
                entry_password = (
                    bw_item.get_card_code() if is_card else bw_item.get_password()
                )

                if is_card:
                    cc_brand = bw_item.get_card_brand()
                    cc_expiry = bw_item.get_card_expiry()
                    cc_holder = bw_item.get_card_holder()

                    if cc_brand != "":
                        entry_tags.append(cc_brand)

                    if cc_expiry != "":
                        try:
                            expiry = parse(cc_expiry).replace(tzinfo=timezone.utc)
                            # Set expiry_time to the last day of the month,
                            # because cards usually expire at the end of the month,
                            # not the beginning
                            entry_expiry_time = expiry + relativedelta(
                                day=31, hour=23, minute=59, second=59
                            )
                            entry_url = cc_expiry

                        except ValueError:
                            logging.warning(
                                f'Skipping card "{item["name"]}" expiry time.'
                            )

                try:
                    if separated and totp_enabled:
                        totp_tag = "totp"
                        totp_entry = totp.add_entry(
                            destination_group=totp.root_group,
                            title=entry_title,
                            username=entry_username,
                            password="",
                            tags=[],
                            notes=notes,
                            # expiry_time=entry_expiry_time,
                            url=entry_url,
                        )

                        # Overwride notes, so passwords DB
                        # would not contain any recovery keys
                        notes = None

                        entry_tags.append(totp_tag)

                        set_totp(totp_entry, totp_secret, totp_settings)
                        set_uris(totp_entry, uris)
                        set_sensitive_attributes(totp_entry, sensitive)

                    entry = kp.add_entry(
                        destination_group=groups_by_id[bw_item.get_folder_id()],
                        title=entry_title,
                        username=entry_username,
                        password=entry_password,
                        notes=notes,
                        tags=entry_tags,
                        expiry_time=entry_expiry_time,
                        url=entry_url,
                    )

                    break
                except Exception as e:
                    if "already exists" in str(e):
                        is_duplicate_title = True
                        continue
                    raise

            if is_identity:
                for k, v in bw_item.get_identity().items():
                    attrs.append(attr(name=k, value=v, protected=False))
            elif is_card and cc_holder:
                attrs.append(attr(name="Card Holder", value=cc_holder, protected=False))
            else:
                set_uris(entry, uris)

                for attachment in bw_item.get_attachments():
                    attachment_raw = subprocess.check_output(
                        [
                            args.bw_path,
                            "get",
                            "attachment",
                            attachment["id"],
                            "--raw",
                            "--itemid",
                            bw_item.get_id(),
                            "--session",
                            args.bw_session,
                        ]
                    )
                    attachment_id = add_binary(attachment_raw)
                    entry.add_attachment(attachment_id, attachment["fileName"])

            if totp_enabled and not separated:
                set_totp(entry, totp_secret, totp_settings)

            set_attributes(entry, attrs)

        except Exception as e:
            logging.warning(
                f'Skipping item named "{item["name"]}" because of this error: {repr(e)}'
            )
            continue

    logging.info("Saving changes to KeePass db.")
    kp.save()

    if separated:
        logging.info("Saving changes to KeePass TOTP db.")
        totp.save()
    logging.info("Export completed.")


def load_folders(folders) -> Dict[str, KPGroup]:
    # sort folders so that in the case of nested folders, the parents would be guaranteed to show up before the children
    folders.sort(key=lambda x: x["name"])

    # dict to store mapping of Bitwarden folder id to keepass group
    groups_by_id: Dict[str, KPGroup] = {}

    # build up folder tree
    folder_root: FolderType.Folder = FolderType.Folder(None)
    folder_root.keepass_group = kp.root_group
    groups_by_id[None] = kp.root_group

    for folder in folders:
        if folder["id"] is not None:
            new_folder: FolderType.Folder = FolderType.Folder(folder["id"])
            # regex lifted from https://github.com/bitwarden/jslib/blob/ecdd08624f61ccff8128b7cb3241f39e664e1c7f/common/src/services/folder.service.ts#L108
            folder_name_parts: List[str] = re.sub(
                r"^\/+|\/+$", "", folder["name"]
            ).split("/")
            FolderType.nested_traverse_insert(
                folder_root, folder_name_parts, new_folder, "/"
            )

    # create keepass groups based off folder tree
    def add_keepass_group(folder: FolderType.Folder):
        parent_group: KPGroup = folder.parent.keepass_group
        new_group: KPGroup = kp.add_group(parent_group, folder.name)
        folder.keepass_group = new_group
        groups_by_id[folder.id] = new_group

    FolderType.bfs_traverse_execute(folder_root, add_keepass_group)

    return groups_by_id


def check_args(args):
    if args.db_keyfile:
        if not os.path.isfile(args.db_keyfile) or not os.access(
            args.db_keyfile, os.R_OK
        ):
            logging.error("Key File for KeePass db is not readable.")
            return False

    if not os.path.isfile(args.bw_path) or not os.access(args.bw_path, os.X_OK):
        logging.error(
            "bitwarden-cli was not found or not executable. Did you set correct '--bw-path'?"
        )
        return False

    return True


def environ_or_required(key):
    return (
        {"default": os.environ.get(key)} if os.environ.get(key) else {"required": True}
    )


parser = ArgumentParser()
parser.add_argument(
    "--bw-session",
    help="Session generated from bitwarden-cli (bw login)",
    **environ_or_required("BW_SESSION"),
)
parser.add_argument(
    "--db-path",
    help="Path to KeePass db. If db does not exists it will be created.",
    **environ_or_required("DB_PATH"),
)
parser.add_argument(
    "--db-password",
    help="Password for KeePass db",
    **environ_or_required("DB_PASSWORD"),
)
parser.add_argument(
    "--totp-db-path",
    help="Path to KeePass TOTP db. If db does not exists it will be created.",
    default=os.environ.get("TOTP_DB_PATH", None),
)
parser.add_argument(
    "--totp-db-password",
    help="Password for KeePass TOTP db",
    default=os.environ.get("TOTP_DB_PASSWORD", None),
)
parser.add_argument(
    "--totp-db-keyfile",
    help="Path to Key File for KeePass TOTP db",
    default=os.environ.get("TOTP_DB_KEYFILE", None),
)
parser.add_argument(
    "--db-keyfile",
    help="Path to Key File for KeePass db",
    default=os.environ.get("DB_KEYFILE", None),
)
parser.add_argument(
    "--bw-path",
    help="Path for bw binary",
    default=os.environ.get("BW_PATH", "bw"),
)
args = parser.parse_args()

check_args(args) and bitwarden2keepass(args)
