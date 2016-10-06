#!/usr/bin/env python3
import sys
import dawg as dawg

from logger import *
logger = setup_logger(__name__, True)
log = logger.info


def load_lines(fname_in):
    lines = ""
    with (sys.stdin.buffer if fname_in == "-" else open(fname_in, "rb")) as file_in:
        lines = file_in.read()
        lines = lines.decode()
        lines = lines.split("\n")

    if lines and lines[-1] == "":
        lines = lines[:-1]

    log("{} lines read".format(len(lines)))
    return lines


def insert_lines_into_dawg(dawg, lines, insert_suffixes=False):
    ninserted = 0
    nlines = len(lines)
    for n, line in enumerate(lines):
        for i in range(1 if not insert_suffixes else len(line)):
            if dawg.insert(line[i:]) > 0:
                ninserted += 1

        if (n % 100) == 0 or n + 1 == len(lines):
            sys.stderr.write("processing line {} of {}\r".format(n + 1, nlines))
            sys.stderr.flush()

    sys.stderr.write("\n")

    log("{} of {} ({}%)) lines inserted".format(ninserted, nlines, 100.0 * ninserted / nlines))
    return ninserted



def main(argv):
    fname_in = "-" if len(argv) < 1 else argv[0]
    fname_out = "-" if len(argv) < 2 else argv[1]

    lines = load_lines(fname_in)

    dog = dawg.DAWG()
    insert_lines_into_dawg(dog, lines)
    dog.compress()

    with (sys.stdout.buffer if fname_out == "-" else open(fname_out, "wb")) as file_out:
        file_out.write(dog.write())

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
