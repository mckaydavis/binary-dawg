import ctypes
import struct
import re
import hashlib
import collections

from logger import *
logger = setup_logger(__name__)
log = logger.info

# chars = "\x00 0123456789abcdefghijklmnopqrstuvwxyz"
chars = """\x00 "$&'(),-./0123456789:;ABCDEFGHIJKLMNOPQRSTUVWXYZ`abcdefghijklmnopqrstuvwxyzāēīōŌū‘…"""

MASK_NUM_CHILDREN = 0x7F
MASK_END_OF_WORD = 0x80

VALID_WORD_REG_EX = re.compile('^[{}]*$'.format(re.escape(chars)))


def valid_string(string):
    return bool(VALID_WORD_REG_EX.match(string))


def chord(char):
    if char not in chars:
        msg = "'{}' not found".format(char)
        log(msg)
        return 0
        assert char in chars, msg
    return int(chars.index(char))


def ordch(cord):
    assert cord < len(chars)
    return chars[cord]


def convert_to_bytes(data):
    struct_format_string = ">{}B".format(len(data))
    buf = ctypes.create_string_buffer(len(data))
    struct.pack_into(struct_format_string, buf, 0, *data)
    return buf


class DAWGNode(object):
    __slots__ = "index children hasher end_of_word".split()

    def __init__(self, end_of_word=False):
        self.end_of_word = end_of_word
        self.children = {}
        self.index = None
        self.hasher = None

    def hexhash(self):
        return self.get_hasher().hexdigest()

    def get_hasher(self):
        if not self.hasher:
            self.hasher = hashlib.sha256()
            if self.end_of_word:
                self.hasher.update(b"\x00")
            for letter, child in sorted(self.children.items()):
                assert ord(letter)
                self.hasher.update(letter.encode())
                self.hasher.update(child.get_hasher().digest())
        return self.hasher

    def set_index(self, val=0, attr='index'):
        todo = [self]
        while todo:
            next_todo = []
            for node in todo:
                setattr(node, attr, val)
                next_todo += [child for child in node.children.values()]
            todo = next_todo

    def count(self, unique=True):
        self.set_index()
        return self._count(unique)

    def _count(self, unique=True):
        if not self.index:
            counts = [child._count(unique) for child in self.children.values()]
            self.index = 1 + sum(counts)
            return self.index
        return 0 if unique else self.index

    def find_terminal_node(self):
        node = self
        while node.children:
            node = list(sorted(node.children.items()))[0][1]
        return node

    def flatten_tree_to_nodes(self):
        self.set_index()
        terminal_node = self.find_terminal_node()
        terminal_node.index = -1

        terminal_node_count = 0
        nodes = [terminal_node]
        todo = [self]
        while todo:
            node = todo.pop(0)
            terminal_node_count += 1 if node.index == -1 else 0

            if node.index:
                continue

            node.index = len(nodes)
            nodes.append(node)

            for letter, child in sorted(node.children.items()):
                todo.append(child)
                # child.nparents += 1

        return nodes

    @staticmethod
    def convert_nodes_to_index_list(nodes):
        assert nodes[0].index == -1
        nodes[0].index = 0
        data = []
        nedges = 0
        skip = 0
        terminal_count = 0
        for i, node in enumerate(nodes):
            nedges += len(node.children)
            assert node.index == i, "index={} len(data)={}".format(node.index, i)

            if node.index == 0:
                assert not node.children
                assert not i
                continue

            assert node.children, "invalid node with no children! i={}".format(i)

            data.append(len(node.children))
            data[-1] |= MASK_END_OF_WORD if node.end_of_word else 0
            for letter, child in sorted(node.children.items()):
                data.append(chord(letter))
                data.append(child.index & 0xFF)
                data.append((child.index >> 8) & 0xFF)
                terminal_count += 0 if child.index else 1

        if logger:
            nnodes = len(nodes)
            nbytes = len(data)
            bytes_per_node = 1.0 * nbytes / nnodes
            edges_per_node = 1.0 * nedges / nnodes
            bytes_per_edge = 1.0 * nbytes / nedges
            log("skip={}".format(skip))
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
        nodes = [DAWGNode(True)]
        pos = 0
        while pos < len(binary_data):
            b0 = binary_data[pos]
            pos += 1

            node = DAWGNode(bool(b0 & MASK_END_OF_WORD))
            node.index = len(nodes)
            nodes.append(node)

            nchildren = b0 & MASK_NUM_CHILDREN
            for i in range(nchildren):
                b0, b1, b2 = binary_data[pos:pos + 3]
                pos += 3
                letter = ordch(b0)
                child_index = b2 << 8 | b1
                node.children[letter] = child_index

        for node in nodes:
            node.children = {letter: nodes[index] for letter, index in node.children.items()}

        root_node = nodes[1]
        terminal_node = nodes[0]

        assert not terminal_node.children, "Terminal node is not childless"
        assert root_node.children, "Root node doesn't have children"
        assert root_node.find_terminal_node() == terminal_node, "Root cannot find terminal_node"
        return root_node

    def dump_strings(self):
        strings = []
        todo = [[("", self)]]
        while todo:
            nodes = todo.pop(0)
            node = nodes[-1][1]
            if node.end_of_word:
                letters = [letter for letter, _ in nodes]
                string = "".join(letters)
                strings.append(string)

            for letter, child in sorted(node.children.items()):
                todo.append(nodes + [(letter, child)])

        return strings

    def insert(self, string):
        node = self
        for letter in string:
            assert letter in chars
            if not letter in node.children:
                node.children[letter] = node = DAWGNode()
            else:
                node = node.children[letter]

        node.end_of_word = True
        return node

    def find(self, string):
        node = self
        for letter in string:
            node = node.children.get(letter, None)
            if node is None:
                break

        return node

    def __contains__(self, string):
        node = self.find(string)
        return node is not None and node.end_of_word

    def compress(self):
        terminal_node = DAWGNode(True)
        hash_table = {terminal_node.hexhash(): terminal_node}
        self_compressed = DAWGNode.recursive_compress(self, hash_table)
        assert self == self_compressed, "recursive compress returned a different node"
        log("compress hashtable len={}".format(len(hash_table)))
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


class DAWG:

    def __init__(self, root_node=None):
        self.root_node = root_node if root_node else DAWGNode()

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

    def dump_strings(self, fname=None, sort=True):
        txt = self.root_node.dump_strings()
        txt = "\n".join(sorted(txt) if sort else txt) + "\n"
        with open(fname, "w") as f:
            f.write(txt)
        return txt

    def insert(self, string):
        assert valid_string(string)
        return self.root_node.insert(string)

    def find(self, string):
        return self.root_node.find(string)

    def __contains__(self, string):
        return string in self.root_node

    def compress(self):
        self.root_node.compress()
