import binaryninja
from binaryninja import interaction, Settings, DownloadProvider
from pathlib import Path

from binaryninjaui import UIAction, UIContext, UIActionContext, UIActionHandler,  Menu
from PySide6.QtCore import QSettings

def open_for_binjahub(ctx: UIActionContext):
    context: UIContext = ctx.context

    if context is None:
        return

    if Settings().contains("plugin.binjahub.url"):
        saved_url = Settings().value("plugin.binjahub.url")
    else:
        saved_url  = "lol"

    link_field =  interaction.TextLineField("URL", "lol")
    token_field = interaction.TextLineField("token", "lol2")

    if not interaction.get_form_input(["Open...", None, link_field, token_field], "open from blabla"):
        return


    link = link_field.result
    token = token_field.result

    name = Settings().get_string("network.downloadProviderName")
    dl = DownloadProvider[name].create_instance()
    result = dl.get("http://195.154.105.118:8000/true.bndb")

    result_file = Path(binaryninja.user_directory()) / 'binjahub' / 'true.bndb'
    result_file.parent.mkdir(parents=True, exist_ok=True)
    with open(result_file, 'wb') as f:
        f.write(result.content)

    context.openFilename(str(result_file))

UIAction.registerAction("Open from binjahub")
UIActionHandler.globalActions().bindAction("Open from binjahub", UIAction(open_for_binjahub))
Menu.mainMenu("File").addAction("Open from binjahub", "Open")
UIContext.registerFileOpenMode("binjahub...", "lol", "Open from binjahub")
