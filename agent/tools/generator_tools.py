import os
import json
import subprocess
import uuid
from typing import Optional, Union
from agent.tools.tools import read_file, list_files, grep, create_file, forge_test, cargo_test, anchor_test, update_file