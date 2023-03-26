import binaryninja
import requests
from binaryninja import interaction, Settings, DownloadProvider
from pathlib import Path
from binaryninjaui import UIAction, UIContext, UIActionContext, UIActionHandler,  Menu
from typing import Optional

import binaryninjaui

from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex
from PySide6.QtWidgets import QApplication, QDialog, QVBoxLayout, QTreeView


class CommentsViewerDialog(QDialog):
    def __init__(self, bndbs):
        super(CommentsViewerDialog, self).__init__()
        # UI
        self.comments_model = CommentsModel(bndbs)

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
        self.setWindowTitle("Comments Viewer")
        self.resize(700, 350)
        flags = self.windowFlags()
        flags |= Qt.WindowMaximizeButtonHint
        flags &= ~Qt.WindowContextHelpButtonHint
        self.setWindowFlags(flags)

    def match_view_double_clicked(self, index):
        if not index.isValid():
            assert False
            return
        entry = self.comments_model.entries[index.row()]
        address = entry["address"]
        #self.bv.navigate(self.bv.file.view, address)
        print("WOOOOO")

class CommentsModel(QAbstractItemModel):
    def __init__(self, bndbs):
        super(CommentsModel, self).__init__()

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
            ("Address", "address", col_addr_field("address")),
            ("Function", "function", col_field("function")),
            ("Comment", "comment", col_field("comment")),
        ]

        self.entries = []
        entry = {}
        #entry["address"] = 123
        #entry["function"] = "function.name"
        #entry["comment"] = "function.comments[addr]"
        #self.entries.append(entry)

        for i in range(50):
            for bndb in bndbs['files']:
                entry = {}
                entry["address"] = 123
                entry["function"] = bndb
                entry["comment"] = " "
                self.entries.append(entry)
            
        #for function in bv.functions:
        #    for addr in function.comments.keys():
        #        entry = {}
        #        entry["address"] = addr
        #        entry["function"] = function.name
        #        entry["comment"] = function.comments[addr]
        #        self.entries.append(entry)

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


#def view_comments(bv):
#    # Qt
#    assert QApplication.instance() is not None
#
#    global dialog
#    dialog = CommentsViewerDialog(bv)
#    dialog.show()
#    dialog.raise_()
#    dialog.activateWindow()





class Binjahub:
    def __init__(self, host: str , port: int):
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


def open_for_binjahub(ctx: UIActionContext):
    context: UIContext = ctx.context

    if context is None:
        return

    link_field =  interaction.TextLineField("URL", "lol")
    token_field = interaction.TextLineField("token", "lol2")

    if not interaction.get_form_input(["Open...", None, link_field, token_field], "open from blabla"):
        return


    link = link_field.result
    token = token_field.result

    #name = Settings().get_string("network.downloadProviderName")
    #dl = DownloadProvider[name].create_instance()
    #result = dl.get("http://195.154.105.118:8000/true.bndb")

    #result_file = Path(binaryninja.user_directory()) / 'binjahub' / 'true.bndb'
    #result_file.parent.mkdir(parents=True, exist_ok=True)
    #with open(result_file, 'wb') as f:
    #    f.write(result.content)
    binjahub = Binjahub("localhost", 5555)
    binjahub.list_bndbs()
    # Qt
    assert QApplication.instance() is not None

    global dialog
    dialog = CommentsViewerDialog(binjahub.list_bndbs())
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    #filename = binjahub.get_bndb("xorddos.bndb")
    #print(filename)
    #context.openFilename(filename)

UIAction.registerAction("Open from binjahub")
UIActionHandler.globalActions().bindAction("Open from binjahub", UIAction(open_for_binjahub))
Menu.mainMenu("File").addAction("Open from binjahub", "Open")
UIContext.registerFileOpenMode("binjahub...", "lol", "Open from binjahub")
