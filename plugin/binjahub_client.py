import os
from pathlib import Path
from typing import Optional

import binaryninja
import binaryninjaui
import requests
from binaryninja import (BackgroundTaskThread, BinaryView, PluginCommand,
                         Settings, interaction, log)
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon
from binaryninja.warp import (WarpContainer, WarpFunction, WarpTarget,
                              run_matcher)
from binaryninjaui import (Menu, UIAction, UIActionContext, UIActionHandler,
                           UIContext)
from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt
from PySide6.QtWidgets import QApplication, QDialog, QTreeView, QVBoxLayout

Settings().register_group("binjahub", "Binjahub")
Settings().register_setting(
    "binjahub.host",
    """
    {
        "title" : "Host",
        "type" : "string",
        "default" : "127.0.0.1",
        "description" : "IP address or hostname of Binjahub server",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)
Settings().register_setting(
    "binjahub.port",
    """
    {
        "title" : "Port",
        "type" : "string",
        "default" : "5555",
        "description" : "Port of Binjahub server",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)
Settings().register_setting(
    "binjahub.secure",
    """
    {
        "title" : "Use TLS",
        "type" : "boolean",
        "default" : false,
        "description" : "Use HTTPS to communicate with Binjahub server",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)

CREDS: dict = {}


class BinjahubViewerDialog(QDialog):
    def __init__(self, context: UIContext = None, bv: BinaryView = None):
        super(BinjahubViewerDialog, self).__init__()
        # UI
        self.context = context

        # Host is set in the binja settings
        host = Settings().get_string("binjahub.host")
        port = int(Settings().get_string("binjahub.port"))
        secure = Settings().get_bool("binjahub.secure")
        self.binjahub = Binjahub(host, port, secure=secure)
        self.context = context
        self.bv = bv

        if bv:
            doubleClicked = self.view_double_clicked_warp
            files = self.binjahub.list_warps()
        elif context:
            doubleClicked = self.view_double_clicked_bndb
            self.context = context
            files = self.binjahub.list_bndbs()
        else:
            # we should never hit this condition
            return

        self.binjahub_viewer_model = BinjahubViewModel(files)
        self.view = QTreeView()
        self.view.setModel(self.binjahub_viewer_model)
        self.view.setSelectionMode(QTreeView.ExtendedSelection)
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.doubleClicked.connect(doubleClicked)

        self.view.setRootIsDecorated(False)
        self.view.setFont(binaryninjaui.getMonospaceFont(self))

        for i in range(len(self.binjahub_viewer_model.files_info)):
            self.view.resizeColumnToContents(i)

        self.view.setSortingEnabled(True)
        self.view.sortByColumn(0, Qt.AscendingOrder)

        layout = QVBoxLayout()
        layout.addWidget(self.view)

        self.setLayout(layout)
        self.setWindowTitle("BinjaHub Viewer")
        self.resize(400, 350)
        flags = self.windowFlags()
        flags |= Qt.WindowMaximizeButtonHint
        flags &= ~Qt.WindowContextHelpButtonHint
        self.setWindowFlags(flags)

    def view_double_clicked_bndb(self, index):
        if not index.isValid():
            assert False
            return
        entry = self.binjahub_viewer_model.entries[index.row()]
        filename = self.binjahub.get_bndb(entry["file"])
        self.context.openFilename(filename)

    def view_double_clicked_warp(self, index):
        if not index.isValid():
            assert False
            return
        containers = list(WarpContainer)
        entry = self.binjahub_viewer_model.entries[index.row()]
        filename = self.binjahub.get_warp(entry["file"])
        print(filename)

        containers[0].add_source(filename)
        run_matcher(self.bv)


class BinjahubViewModel(QAbstractItemModel):
    def __init__(self, bndbs):
        super(BinjahubViewModel, self).__init__()

        def col_field(key, default=None):
            def f(i):
                entry = self.entries[i]
                result = entry[key]
                if result is None:
                    return default
                return result

            return f

        def col_field_fmt(key, fmt):
            return lambda i: fmt.format(self.entries[i][key])

        def col_addr_field(key):
            return lambda i: "{:x}".format(self.entries[i][key])

        # Column name, sort key, display function
        self.files_info = [
            ("File", "file", col_field("file")),
            ("Size", "size", col_field("size")),
        ]

        self.entries = []
        entry = {}

        for bndb in bndbs:
            entry = {}
            entry["file"] = bndb
            entry["size"] = bndbs[bndb]
            self.entries.append(entry)

    def index(self, row, col, parent):
        if parent.isValid():
            # No children
            return QModelIndex()

        if row >= len(self.entries):
            return QModelIndex()
        if col >= len(self.files_info):
            return QModelIndex()

        return self.createIndex(row, col)

    def parent(self, index):
        # Flat tree, no parent
        return QModelIndex()

    def rowCount(self, parent):
        # No children
        if parent.isValid():
            return 0
        return len(self.entries)

    def columnCount(self, parent):
        return len(self.files_info)

    def data(self, index, role):
        if index.row() >= len(self.entries):
            return None

        name, key, display = self.files_info[index.column()]
        if role == Qt.DisplayRole:
            return display(index.row())
        return None

    def headerData(self, section, orientation, role):
        if role != Qt.DisplayRole:
            return None
        if orientation != Qt.Horizontal:
            return None

        name, key, display = self.files_info[section]
        return name

    def sort(self, col, order):
        self.beginResetModel()

        name, key, display = self.files_info[col]
        self.entries.sort(key=lambda k: k[key], reverse=(order != Qt.AscendingOrder))

        self.endResetModel()


class Binjahub:
    def __init__(self, host: str, port: int, secure=False):
        self.host = host
        self.port = port
        self.token = None
        self.base_url = f"http{'s' if secure else ''}://{self.host}:{self.port}"
        if self.needs_auth():
            self.prompt_creds()

    def prompt_creds(self):
        global CREDS
        while True:
            if not CREDS:
                user = interaction.get_text_line_input("Username", "LDAP Credentials")
                password = interaction.get_text_line_input(
                    "Password", "LDAP Credentials"
                )
            else:
                user, password = CREDS["username"], CREDS["password"]
            if user and password:
                if self.auth(user, password):
                    CREDS = {"username": user, "password": password}
                    break
                CREDS = {}
            else:
                break
            log.log_alert("Incorrect credentials!")

    def auth(self, username, password):
        r = self.post("login", data={"username": username, "password": password})
        if not r:
            return False
        if "access_token" not in r:
            return False
        self.token = r["access_token"]
        return True

    def needs_auth(self):
        r = self.get("auth-required")
        if r and r["auth_required"]:
            return True
        return False

    def get(self, url=""):
        if self.token:
            headers = {"Authorization": f"Bearer {self.token}"}
        else:
            headers = None
        url = f"{self.base_url}/{url}" if url else self.base_url
        r = requests.get(url, headers=headers)
        return self.__resolve_req(r)

    def post(self, url="", **kwargs):
        if self.token:
            headers = {"Authorization": f"Bearer {self.token}"}
        else:
            headers = None
        url = f"{self.base_url}/{url}" if url else self.base_url
        r = requests.post(url, headers=headers, **kwargs)
        return self.__resolve_req(r)

    def list_bndbs(self) -> dict:
        if dbs := self.get("bndb"):
            return dbs
        return {}

    def get_bndb(self, bndb) -> Optional[str]:
        data = self.get(f"bndb/{bndb}")
        if not data:
            return None
        file = Path(binaryninja.user_directory()) / "binjahub" / bndb
        file.parent.mkdir(parents=True, exist_ok=True)
        open(file, "wb").write(data)
        return str(file)

    def upload_bndb(self, bndb):
        log.log_info(f"Uploading {bndb}")
        file = {"file": open(bndb, "rb")}
        response = self.post("bndb", files=file)
        if not response:
            log.log_alert("Unable to save database!")
            return
        log.log_info(f"Saved database to {self.host}")

    def list_warps(self) -> dict:
        if dbs := self.get("warp"):
            return dbs
        return {}

    def get_warp(self, warp) -> Optional[str]:
        data = self.get(f"warp/{warp}")
        if not data:
            return None
        file = Path(binaryninja.user_directory()) / "binjahub" / "WARP" / warp
        file.parent.mkdir(parents=True, exist_ok=True)
        open(file, "wb").write(data)
        return str(file)

    def upload_warp(self, warp):
        log.log_info(f"Uploading {warp}")
        file = {"file": open(warp, "rb")}
        response = self.post("warp", files=file)
        if not response:
            log.log_alert(f"Unable to upload {warp}!")
            return
        log.log_info(f"Saved warp signature to {self.host}")

    def __resolve_req(self, r: requests.Response):
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except requests.JSONDecodeError:
            data = r.content
        return data


class BackgroundTask(BackgroundTaskThread):
    def __init__(self, message, func, *args):
        BackgroundTaskThread.__init__(self, message)
        self.func = func
        self.args = args

    def run(self):
        self.func(self.args[0])


def open_from_binjahub(ctx: UIActionContext):
    context: UIContext = ctx.context
    if context is None:
        return

    assert QApplication.instance() is not None

    global dialog  # type: ignore
    dialog = BinjahubViewerDialog(context)  # type: ignore
    dialog.show()  # type: ignore
    dialog.raise_()  # type: ignore
    dialog.activateWindow()  # type: ignore


def push_to_binjahub(bv):
    if bv.file.database is None:
        interaction.show_message_box(
            "Binjahub",
            "Please save the database first",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    bndb = bv.file.database.file.filename
    host = Settings().get_string("binjahub.host")
    port = int(Settings().get_string("binjahub.port"))
    secure = Settings().get_bool("binjahub.secure")
    binjahub = Binjahub(host, port, secure=secure)
    background_task = BackgroundTask("Binjahub upload...", binjahub.upload_bndb, bndb)
    background_task.start()


def list_warp_signatures(bv):
    global dialog
    dialog = BinjahubViewerDialog(context=None, bv=bv)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()


def push_warp(bv):
    # create WARP
    warp = Path(bv.file.filename).name.replace(" ", "_")
    file = Path(binaryninja.user_directory()) / "binjahub" / "WARP" / f"{warp}.warp"
    file.parent.mkdir(parents=True, exist_ok=True)

    # may remove later
    try:
        os.remove(str(file))
    except FileNotFoundError:
        pass

    container = WarpContainer.all()[0]
    source = container.add_source(str(file))
    target = WarpTarget(bv.platform)

    target_functions = [
        WarpFunction(function)
        for function in bv.functions
        if "sub_" not in function.name
    ]

    container.add_functions(target, source, target_functions)
    container.commit_source(source)

    host = Settings().get_string("binjahub.host")
    port = int(Settings().get_string("binjahub.port"))
    secure = Settings().get_bool("binjahub.secure")

    binjahub = Binjahub(host, port, secure)
    background_task = BackgroundTask("Binjahub upload...", binjahub.upload_warp, file)
    background_task.start()


def pull_warps(bv):
    host = Settings().get_string("binjahub.host")
    port = int(Settings().get_string("binjahub.port"))
    secure = Settings().get_bool("binjahub.secure")

    binjahub = Binjahub(host, port, secure)

    warps = binjahub.list_warps()
    containers = list(WarpContainer)

    for warp in warps:
        print(f"downloading {warp}")
        file = binjahub.get_warp(warp)
        containers[0].add_source(file)

    run_matcher(bv)


UIAction.registerAction("Open from binjahub")
UIActionHandler.globalActions().bindAction(
    "Open from binjahub", UIAction(open_from_binjahub)
)
Menu.mainMenu("File").addAction("Open from binjahub", "Open")
UIContext.registerFileOpenMode("Binjahub", "Open from Binjahub", "Open from binjahub")

PluginCommand.register("Push to Binjahub", "Push to Binjahub", push_to_binjahub)

PluginCommand.register(
    "List WARP signatures on BinjaHub",
    "List WARP signatures on BinjaHub",
    list_warp_signatures,
)
PluginCommand.register("Push WARP to BinjaHub", "Push WARP to BinjaHub", push_warp)
PluginCommand.register("Apply all BinjaHub WARPs", "Apply BinjaHub WARPs", pull_warps)
