from distutils.core import setup
import py2exe

setup(windows=[{"script": "run_app.py"}],  options={"py2exe": {"includes" : ["socket", "time", "rsa", "hashlib", "pickle", "json", "threading", "subprocess", "os", "queue"], "bundle_files": 1}})