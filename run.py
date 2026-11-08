"""Start NetAudit: python run.py  (run as administrator/root for OS detection and UDP checks)."""
import os
import threading
import webbrowser

import uvicorn

HOST = os.environ.get("NETAUDIT_HOST", "127.0.0.1")
PORT = int(os.environ.get("NETAUDIT_PORT", "8808"))

if __name__ == "__main__":
    if HOST not in ("127.0.0.1", "localhost") and not (os.environ.get("NETAUDIT_USER") and os.environ.get("NETAUDIT_PASSWORD")):
        print(f"WARNING: NETAUDIT_HOST={HOST} exposes this dashboard beyond your own machine, "
              "but NETAUDIT_USER/NETAUDIT_PASSWORD are not set, so anyone who can reach it can run scans "
              "and read every finding. Set both environment variables before doing this on a shared network.")
    if os.environ.get("NETAUDIT_NO_BROWSER") != "1":
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{HOST}:{PORT}")).start()
    uvicorn.run("app.main:app", host=HOST, port=PORT, log_level="warning")
