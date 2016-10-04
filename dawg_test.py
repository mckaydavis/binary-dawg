#!/usr/bin/env python3
import sys
import dawg
import ctypes
import pickle
import collections

from logger import *
logger = setup_logger(__name__)
log = logger.info


def test_exists(dog, string, expected=True):
    success = (string in dog) == expected
    status = "PASS" if success else "FAIL"
    if not success:
        log("{}: exists({}) should be {}, is {}".format(status, string, expected, success))
    return 1 if success else 0


def test_dawg(dog, strings=[]):
    passed = 0

    all_count = dog.root_node.count(False)
    unique_count = dog.root_node.count(True)
    compression = 100.0 * unique_count / all_count
    ratio = all_count / unique_count
    log("Dawg all-count={}  unique={} compresion ratio={:.2f} to 1 ({:5.2f}%), ".format(all_count, unique_count, ratio, compression))

    for string in strings:
        passed += test_exists(dog, string)
        passed += test_exists(dog, string + "_random_lasdjkf", False)

    log("PASS: {}, FAIL: {}".format(passed, len(strings) * 2 - passed))

    num_failed = len(strings) * 2 - passed

    return num_failed


def load_lines(arg1):
    lines = ""
    with open(arg1, 'r') as f:
        lines = f.read()

    lines = lines.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]

    return lines


def filter_lines(lines):
    filtered_lines = []
    for line in lines:
        if not dawg.valid_string(line):
            log('discarding line "{}"'.format(line))
            continue
        filtered_lines.append(line)
    return filtered_lines


def main(argv):
    nfailed = 0

    arg1 = "words.txt" if not argv else argv[0]

    dog = dawg.DAWG()
    lines = load_lines(arg1)
    nloaded = len(lines)
    log("{} lines loaded".format(nloaded))

    log("filtering lines")
    lines = filter_lines(lines)
    nlines = len(lines)

    insert_suffixes = True
    insert_suffixes = False

    ninserted = 0
    for n, line in enumerate(lines):
        for i in range(1 if not insert_suffixes else len(line)):
            dog.insert(line[i:])
            ninserted += 1

        if (n % 100) == 0 or n + 1 == len(lines):
            sys.stderr.write("inserted line {} of {}\r".format(n + 1, nlines))
            sys.stderr.flush()

    sys.stderr.write("\n")

    log("{} of {} ({}%)) lines inserted".format(ninserted, nlines, 100.0 * ninserted / nlines))

    nfailed += test_dawg(dog, lines)

    dumpf = "dump0.txt"
    log("dump to {}".format(dumpf))
    dog.dump_strings(dumpf)

    log("compress")
    dog.compress()

    nfailed += test_dawg(dog, lines)

    dumpf = "dump1.txt"
    log("dump to {}".format(dumpf))
    dog.dump_strings(dumpf)

    bin_fname = arg1 + ".dawg"
    log("write to binary {}".format(bin_fname))
    dog.write(bin_fname)

    log("read from binary {}".format(bin_fname))
    dog2 = dawg.DAWG.read(bin_fname)

    dumpf = "dump2.txt"
    log("dump binary to {}".format(dumpf))
    dog2.dump_strings(dumpf)

    log("test binary")
    nfailed += test_dawg(dog2, lines)

    return -1 if nfailed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
