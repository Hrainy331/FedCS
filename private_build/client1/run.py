import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fedcs_private.runtime import main

if __name__ == "__main__":
    main(default_pid=1)
