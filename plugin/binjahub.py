import binaryninja
import requests
from binaryninja import PluginCommand
from pathlib import Path
from binaryninjaui import UIAction, UIContext, UIActionContext, UIActionHandler, Menu
from typing import Optional

import binaryninjaui

from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex
from PySide6.QtWidgets import QApplication, QDialog, QVBoxLayout, QTreeView


class BinjahubViewerDialog(QDialog):
    def __init__(self, context):
        super(BinjahubViewerDialog, self).__init__()
        # UI
        self.context = context

        self.binjahub = Binjahub("10.66.66.5", 5555)
        bndbs = self.binjahub.list_bndbs()
        self.comments_model = BinjahubViewModel(bndbs)

        self.match_view = QTreeView()
        self.match_view.setModel(self.comments_model)

        self.match_view.setSelectionMode(QTreeView.ExtendedSelection)

        self.match_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.match_view.doubleClicked.connect(self.match_view_double_clicked)

        self.match_view.setRootIsDecorated(False)
        self.match_view.setFont(binaryninjaui.getMonospaceFont(self))

        for i in range(len(self.comments_model.comments_info)):
            self.match_view.resizeColumnToContents(i)

        self.match_view.setSortingEnabled(True)
        self.match_view.sortByColumn(0, Qt.AscendingOrder)

        layout = QVBoxLayout()
        layout.addWidget(self.match_view)

        self.setLayout(layout)
        self.setWindowTitle("Binjahub Viewer")
        self.resize(400, 350)
        flags = self.windowFlags()
        flags |= Qt.WindowMaximizeButtonHint
        flags &= ~Qt.WindowContextHelpButtonHint
        self.setWindowFlags(flags)

    def match_view_double_clicked(self, index):
        if not index.isValid():
            assert False
            return
        entry = self.comments_model.entries[index.row()]
        filename = self.binjahub.get_bndb(entry['bndb'])
        self.context.openFilename(filename)


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
        self.comments_info = [
            ("BNDB", "bndb", col_field("bndb")),
            ("Size", "size", col_field("size")),
        ]

        self.entries = []
        entry = {}

        for bndb in bndbs:
            entry = {}
            entry["bndb"] = bndb
            entry["size"] = bndbs[bndb]
            self.entries.append(entry)

    def index(self, row, col, parent):
        if parent.isValid():
            # No children
            return QModelIndex()

        if row >= len(self.entries):
            return QModelIndex()
        if col >= len(self.comments_info):
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
        return len(self.comments_info)

    def data(self, index, role):
        if index.row() >= len(self.entries):
            return None

        name, key, display = self.comments_info[index.column()]
        if role == Qt.DisplayRole:
            return display(index.row())
        return None

    def headerData(self, section, orientation, role):
        if role != Qt.DisplayRole:
            return None
        if orientation != Qt.Horizontal:
            return None

        name, key, display = self.comments_info[section]
        return name

    def sort(self, col, order):
        self.beginResetModel()

        name, key, display = self.comments_info[col]
        self.entries.sort(key=lambda k: k[key], reverse=(order != Qt.AscendingOrder))

        self.endResetModel()


class Binjahub:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def list_bndbs(self) -> dict:
        r = requests.get(f"http://{self.host}:{self.port}/bndb")
        data = r.json()
        print(data)
        return data

    def get_bndb(self, bndb) -> Optional[str]:
        r = requests.get(f"http://{self.host}:{self.port}/bndb/{bndb}")
        if r.status_code != 200:
            return None
        file = Path(binaryninja.user_directory()) / 'binjahub' / bndb
        file.parent.mkdir(parents=True, exist_ok=True)
        open(file, 'wb').write(r.content)
        return str(file)

    def upload_bndb(self, filename, bndb):
        file = {'file': open(bndb, 'rb')}
        response = requests.post(f"http://{self.host}:{self.port}/bndb", files=file)
        print(response.json())


def open_for_binjahub(ctx: UIActionContext):
    context: UIContext = ctx.context

    if context is None:
        return

    assert QApplication.instance() is not None

    global dialog
    dialog = BinjahubViewerDialog(context)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()


def push_to_binjahub(bv):
    filename = bv.file.filename.split('/')[-1]
    absolut_file = f"{binaryninja.user_directory()}/binjahub/{filename}"
    bndb = f"{absolut_file}.bndb"
    bv.save(bndb)

    binjahub = Binjahub("10.66.66.5", 5555)
    binjahub.upload_bndb(filename, bndb)


UIAction.registerAction("Open from binjahub")
UIActionHandler.globalActions().bindAction(
    "Open from binjahub", UIAction(open_for_binjahub)
)
Menu.mainMenu("File").addAction("Open from binjahub", "Open")
UIContext.registerFileOpenMode("Binjahub", "Open from Binjahub", "Open from binjahub")

PluginCommand.register("Push to Binjahub", "Push to Binjahub", push_to_binjahub)
