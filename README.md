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
![image](https://github.com/matteyeux/binjahub/assets/8758978/6fbce05d-a917-41d4-b6b6-a9578019dc6f)

You can now open a new binary, then from the command palette you can "Push to Binjahub".

In a new Binary Ninja window, you should have a new button "Open from Binjahub":

![image](https://github.com/matteyeux/binjahub/assets/8758978/c7fde0ff-d323-4346-97d5-10ff0e583412)

Double-click on the target BNDB and it will be opened in a new BinaryView.

