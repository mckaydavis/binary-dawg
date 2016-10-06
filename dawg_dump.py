#!/usr/bin/env python3
import sys
import dawg as dawg

from logger import *
logger = setup_logger(__name__)
log = logger.info


def main(argv):
    fname_in = "-" if len(argv) < 1 else argv[0]
    fname_out = "-" if len(argv) < 2 else argv[1]

    data = []
    with (sys.stdin.buffer if fname_in == "-" else open(fname_in, "rb")) as file_in:
        data = file_in.read()

    dog = dawg.DAWG.from_binary(data)

    with (sys.stdout.buffer if fname_out == "-" else open(fname_out, "wb")) as file_out:
        file_out.write(dog.dump_strings().encode())

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
