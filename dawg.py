import ctypes
import struct
import re
import hashlib
import collections

from logger import *
logger = setup_logger(__name__)
log = logger.info

# chars = "\x00 0123456789abcdefghijklmnopqrstuvwxyz"
NULL_CHAR = "\x00"
CHARSET = NULL_CHAR + """ "$&'(),-./0123456789:;ABCDEFGHIJKLMNOPQRSTUVWXYZ`abcdefghijklmnopqrstuvwxyzāēīōŌū‘…"""

MASK_END_OF_DATA = 0x80
MASK_DATA = 0x7F

VALID_WORD_REG_EX = re.compile('^[{}]*$'.format(re.escape(CHARSET)))



def valid_string(string):
    return bool(VALID_WORD_REG_EX.match(string))


def chord(char):
    if char not in CHARSET:
        msg = "'{}' not found".format(char)
        log(msg)
        return 0
        assert char in CHARSET, msg
    return int(CHARSET.index(char))


def ordch(cord):
    assert cord < len(CHARSET), "cord={}, len(chars)={}".format(cord, len(CHARSET))
    return CHARSET[cord]


def convert_to_bytes(data):
    struct_format_string = ">{}B".format(len(data))
    buf = ctypes.create_string_buffer(len(data))
    struct.pack_into(struct_format_string, buf, 0, *data)
    return buf


class DAWGNode(object):
    __slots__ = "index letter children hasher nchildren nparents".split()

    def __init__(self, letter=NULL_CHAR, index=None):
        self.index = index
        self.letter = letter
        self.children = {}
        self.hasher = None
        self.nchildren = 0
        self.nparents = 0

    def hexhash(self):
        return self.get_hasher().hexdigest()

    def get_hasher(self):
        if not self.hasher:
            self.hasher = hashlib.sha256()
            self.hasher.update(self.letter.encode())
            for letter, child in sorted(self.children.items()):
                self.hasher.update(child.get_hasher().digest())
        return self.hasher

    # Set attribute on node and all descendants
    def set_attr(self, attr, val):
        todo = [self]
        while todo:
            next_todo = []
            for node in todo:
                setattr(node, attr, val)
                next_todo += [child for child in node.children.values()]
            todo = next_todo

    def count(self, unique=True):
        self.set_attr('nchildren', 0)
        return self.recursive_count(unique)

    def recursive_count(self, unique):
        if not self.nchildren:
            counts = [child.recursive_count(unique) for child in self.children.values()]
            self.nchildren = 1 + sum(counts)
            return self.nchildren
        return 0 if unique else self.nchildren

    def first_child(self):
        if not self.children:
            return None
        return next (iter (self.children.values()))


    def find_terminal_node(self):
        node = self
        while node.children:
            node = node.first_child()
        return node


    def flatten_tree_to_nodes(self):
        self.set_attr('index', 0)
        # Put the terminal node first in the node list
        nodes = [self.find_terminal_node()]
        nodes[-1].index = len(nodes)
        todo = [self]
        while todo:
            node = todo.pop(0)
            if node.index:
                continue

            nodes.append(node)
            node.index = len(nodes)
            todo += list(node.children.values())

        log("Flatten nnodes={}".format(len(nodes)))

        return nodes


    def log_parent_info(self, extra=False):
        self.count_parents()
        nodes = self.flatten_tree_to_nodes()
        nparents = collections.Counter()
        total = sum([node.nparents for node in nodes])
        for node in nodes:
            nparents[(node.nparents,len(node.children))] += 1

        for k,v in sorted(nparents.items()):
            log("{} nparents[{}] = {}".format(k[0], k,v))

        for node in nodes:
            if node.nparents > 133:
                log("[{}] = {}".format(node.nparents, " ".join(node.dump_strings(debug=True))))
            if extra and node.nparents == 1 and len(node.children) == 1:
                log("1-1: idx={}, letter={}, keys={}, strings=({})".format(node.index, node.letter, node.keys(), ", ".join(node.dump_strings())))


        log("total_nparents={}".format(total))
        log("sum 32 top_parents={}".format(sum([k[0] for k in list(sorted(nparents.keys()))[-32:]])))
        log("sum 64 top_parents={}".format(sum([k[0] for k in list(sorted(nparents.keys()))[-64:]])))
        log("sum 128 top_parents={}".format(sum([k[0] for k in list(sorted(nparents.keys()))[-128:]])))

    def count_parents(self):
        self.set_attr('nparents', 0)
        self.recursive_count_parents()
        self.nparents = 0

    def recursive_count_parents(self):
        self.nparents += 1
        if self.nparents == 1:
            for child in self.children.values():
                child.recursive_count_parents()

    @staticmethod
    def convert_nodes_to_index_list(nodes):
        data = []
        def mark_eod():
            nonlocal data
            assert data
            assert data[-1] & MASK_END_OF_DATA == 0, "End of Data marker already present"
            data[-1] |= MASK_END_OF_DATA


        assert nodes[0].index == 1

        nedges = 0
        terminal_count = 0

        nnodes = len(nodes)
        data.append(nnodes & 0xFF)
        data.append((nnodes >> 8) & 0xFF)
        mark_eod()

        for i, node in enumerate(nodes):
            nedges += len(node.children)
            assert node.index-1 == i, "index={} len(data)={}".format(node.index, i)

            if node.index == 1:
                assert not node.children
                assert not i
                continue

            assert node.children, "invalid node with no children! i={}".format(i)

            for letter in node.letter:
                data.append(chord(letter))

            mark_eod()

            for letter, child in sorted(node.children.items()):
                child_index = child.index - 1
                data.append(child_index & 0xFF)
                data.append((child_index >> 8) & 0xFF)
                if child_index == 0:
                    assert not child.children
                    terminal_count += 1

            mark_eod()


        if logger:
            nnodes = len(nodes)
            nbytes = len(data)
            bytes_per_node = 1.0 * nbytes / nnodes
            edges_per_node = 1.0 * nedges / nnodes
            bytes_per_edge = 1.0 * nbytes / nedges
            log("nnodes={}".format(nnodes))
            log("nbytes={}".format(nbytes))
            log("nedges={}".format(nedges))
            log("edges_per_node={}".format(edges_per_node))
            log("bytes_per_node={}".format(bytes_per_node))
            log("bytes_per_edge={}".format(bytes_per_edge))
            log("terminal_count={} ({:.2f}% could be saved if nnodes < {})".format(terminal_count, 100.0 * terminal_count / nbytes, 2**15))

        return data

    def flatten(self):
        nodes = self.flatten_tree_to_nodes()
        index_list = DAWGNode.convert_nodes_to_index_list(nodes)
        return index_list

    def to_binary(self):
        index_list = self.flatten()
        byte_data = convert_to_bytes(index_list)
        return byte_data

    @staticmethod
    def from_binary(binary_data):

        def eat():
            nonlocal pos
            pos += 1
            return binary_data[pos-1]

        def eat_7bits_and_eod():
            val = eat()
            return (int(val) & MASK_DATA), bool(int(val) & MASK_END_OF_DATA == MASK_END_OF_DATA)

        def eat_15bits_and_eod():
            b0 = eat()
            b1, eod = eat_7bits_and_eod()
            return b1 << 8 | b0, eod
        pos = 0


        nnodes, eod = eat_15bits_and_eod()
        log("from_binary nnodes={}".format(nnodes))

        # Initialize with terminal node
        nodes = [DAWGNode(index=i+1) for i in range(nnodes)]

        idx = 1
        while pos < len(binary_data):
            node = nodes[idx]
            idx += 1
            node.letter = ""
            eod = False
            while not eod:
                data, eod = eat_7bits_and_eod()
                node.letter += ordch(data)

            eod = False
            node.children = []
            while not eod:
                child_index, eod = eat_15bits_and_eod()
                node.children.append(child_index)

        for node in nodes:
            node.children = {nodes[index].letter[0]: nodes[index] for index in node.children}

        root_node = nodes[1]
        terminal_node = nodes[0]

        #log("load terminal_count={}".format(terminal_count))

        assert not terminal_node.children, "Terminal node is not childless"
        assert root_node.children, "Root node doesn't have children"
        assert root_node.find_terminal_node() == terminal_node, "Root cannot find terminal_node"
        return root_node

    def dump_strings(self, string="", debug=False):
        if debug and not self.children:
            string = "<" + string.replace(NULL_CHAR, "*") + ">"
            return [string]

        string = string + self.letter
        strings = [] if self.children else [string[1:-1]]
        for child in self.sorted_children():
            strings += child.dump_strings(string, debug)
        return strings


    def insert(self, string):
        node = self
        assert len(string) and string[-1] == NULL_CHAR and NULL_CHAR not in string[:-1]
        for letter in string:
            assert letter in CHARSET
            if not letter in node.children:
                node.children[letter] = node = DAWGNode(letter)
            else:
                node = node.children[letter]
        #node.end_of_word = True
        return node

    def find(self, string):
        node = self
        spos = 0
        slen = len(string)
        npos = 0
        while node and spos < slen and string[spos] == node.letter[npos]:
            spos += 1
            npos += 1
            if npos == len(node.letter) and spos < slen:
                npos = 0
                node = node.children.get(string[spos], None)

        return node


    def keys(self):
        return "".join(sorted(self.children.keys()))

    def sorted_children(self):
        return [v for k,v in sorted(self.children.items())]

    def __contains__(self, string):
        assert NULL_CHAR not in string
        node = self.find(NULL_CHAR + string + NULL_CHAR)
        return node and not node.children


    def compress(self):
        # self.log_parent_info()
        terminal_node = DAWGNode('\x00')
        hash_table = {terminal_node.hexhash(): terminal_node}
        self_compressed = DAWGNode.recursive_compress(self, hash_table)
        assert self == self_compressed, "recursive compress returned a different node"
        log("compress hashtable len={}".format(len(hash_table)))
        self = DAWGNode.compress_sticks(self)
        # self.log_parent_info()
        return self_compressed

    @staticmethod
    def recursive_compress(node, hash_table):
        node.children = {letter: DAWGNode.recursive_compress(child, hash_table) for letter, child in sorted(node.children.items())}
        hash_value = node.get_hasher().hexdigest()
        if hash_value in hash_table:
            node = hash_table[hash_value]
        else:
            hash_table[hash_value] = node
        return node

    @staticmethod
    def compress_sticks(node):
        node.set_attr('index', 0)
        node.count_parents()
        todo = [node]
        discarded = 0
        nnodes = 0
        while todo:
            node = todo.pop(0)
            assert node.index != -1
            if node.index:
                continue
            nnodes += 1
            node.index = nnodes

            first_child = node.first_child()
            while first_child and len(node.children) == 1 and first_child.nparents == 1:
                assert first_child.index == 0, "compress_sticks first_child already visited"
                first_child.index = -1
                discarded += 1
                node.letter += first_child.letter
                node.children = first_child.children
                first_child = node.first_child()

            todo += list(node.children.values())

        log("compress_sticks total={}, nnodes={} ({:.2f}%), discarded={} ({:.2f}%), ".format(nnodes + discarded, nnodes, 100.0*nnodes/(discarded+nnodes), discarded, 100.0*discarded/(discarded+nnodes)))

        return node





class DAWG:

    def __init__(self, root_node=None):
        self.root_node = root_node if root_node else DAWGNode('\x00')

    def write(self, fname=None):
        byte_data = self.root_node.to_binary()
        if fname:
            with open(fname, "wb") as f:
                f.write(byte_data)
        return byte_data

    @staticmethod
    def read(fname):
        binary_data = None
        with open(fname, "rb") as f:
            binary_data = f.read()

        return DAWG.from_binary(binary_data)

    @staticmethod
    def from_binary(binary_data):
        root_node = DAWGNode.from_binary(binary_data)
        dawg = DAWG(root_node)
        return dawg

    def dump_strings(self, fname=None, sort=False):
        txt = self.root_node.dump_strings()
        txt = "\n".join(sorted(txt) if sort else txt) + "\n"
        if fname is not None:
            with open(fname, "w") as f:
                f.write(txt)
        return txt

    def insert(self, string):
        assert valid_string(string)
        return self.root_node.insert(string + NULL_CHAR)

    def find(self, string):
        return self.root_node.find(string)

    def __contains__(self, string):
        return string in self.root_node

    def compress(self):
        self.root_node.compress()
