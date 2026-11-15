"""The echo server, 5 s late: a bridge that is slow to start (a cold npx, a server that hangs for a while)."""
import os, runpy, time
time.sleep(5)
runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "echo_server.py"), run_name="__main__")
