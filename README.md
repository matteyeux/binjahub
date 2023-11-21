# binjahub

Manage Binary Ninja databases (Poor man's Binary Ninja Enterprise).


This repository is split in two parts:
- binjahub : the server.
- plugin : the plugin, acting as a client.

### Server

Start the binjahub server with poetry : `cd binjahub && poetry install`

Then start the server:

```
 » poetry run binjahub/main.py
INFO:     Started server process [5939]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:5555 (Press CTRL+C to quit)
```

### Plugin

Copy the plugin to `~/.binaryninja/plugins` (support for Windows : ETA SON).

Configure the settings for the plugin :

![sc1](https://github.com/matteyeux/binjahub/assets/8758978/ad8391a4-dbf5-4aac-9f6b-cefa91a158bf)

You can now open a new binary, then from the command palette you can "Push to Binjahub".

In a new Binary Ninja window, you should have a new button "Open from Binjahub":

![sc2](https://github.com/matteyeux/binjahub/assets/8758978/c2d7edc5-dab0-4396-86e4-612fb8028639)

Double-click on the target BNDB and it will be opened in a new BinaryView.

