# Shalom Rosh, 308154418, Polina Rabinovich, 341095982
import hashlib
import base64
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class MerkleTree:

    def __init__(self):
        """
        init the members of the MerkleTree.
        """
        self.leaves = []
        self.levels_data = None
        self.is_tree = False
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                    backend=default_backend())

    def new_leaf(self, value):
        """
        add a new leaf to the list of leaves [in time of adding flg the
        self.is_tree = False in order to now that the tree ndd to be recalculated]
        :param value: the value to add to leaves list [after hashing]
        """
        self.leaves.append(hashlib.sha256(value.encode()).hexdigest())
        self.is_tree = False

    def __get_level_params(self):
        """
        help function to calculate the level params.
        :return: level_size: the size of the level
        :return: odd_leave: the leave to add to the next level [if level_size is odd]
        :return: flg: tell us if we should add to the next level
        :return: lefts, rights: arrays of left and right leaves to add to the next level
        """
        level_size = len(self.levels_data[0])
        flg, odd_leave, size = (False, None, level_size) if not level_size & 1 \
            else (True, self.levels_data[0][-1], level_size - 1)
        return flg, odd_leave, self.levels_data[0][0:size:2], self.levels_data[0][1:size:2]

    def __create_levels(self):
        """
        create new level in the tree.
        """
        next_level = [[]]
        flg, odd_leave, lefts, rights = self.__get_level_params()
        for left, right in zip(lefts, rights):
            next_level[0].append(hashlib.sha256(left.encode() + right.encode()).hexdigest())
        next_level[0].append(odd_leave) if flg else None
        self.levels_data = next_level + self.levels_data

    def __create_tree(self):
        """
        create the tree [level by level] from the list of leaves.
        """
        if len(self.leaves) > 0:
            self.levels_data = [self.leaves]
            while len(self.levels_data[0]) > 1:
                self.__create_levels()
            self.is_tree = True

    def get_root(self):
        """
        get the root [if the tree is created, else create the tree].
        :return: root: the root in self.levels_data[0][0]
        """
        self.__create_tree() if not self.is_tree else None
        return '' if self.levels_data is None else self.levels_data[0][0]

    def create_proof(self, leaf_index):
        """
        create the proof of inclusion.
        :param leaf_index: leaf to create the proof until it.
        :return: proof_of_inclusion: proof of inclusion according to the assignment demands
        """
        proof_of_inclusion = ''
        self.__create_tree() if not self.is_tree else None
        if self.levels_data is None or (0 < leaf_index < len(self.leaves) - 1):
            return proof_of_inclusion
        proof_of_inclusion = self.get_root()
        for level in reversed(self.levels_data):
            if leaf_index == len(level) - 1 and len(level) & 1:
                leaf_index = math.floor(leaf_index / 2)
                continue
            hexed_value = level[leaf_index - 1 if leaf_index % 2 else leaf_index + 1]
            coefficient = '0' if leaf_index % 2 else '1'
            proof_of_inclusion += ' ' + coefficient + hexed_value
            leaf_index = math.floor(leaf_index / 2)
        return proof_of_inclusion

    @staticmethod
    def check_proof(leaf, proof):
        """
        check proof of inclusion
        :param leaf
        :param proof
        :return: True/False depending if we able to proof
        """
        ans = hashlib.sha256(leaf.encode()).hexdigest()
        proof_to_list = proof.split(' ')
        root = proof_to_list[0]
        for i in proof_to_list[1:]:
            flg = i[1:] + ans if i[0] == '0' else ans + i[1:]
            ans = str(hashlib.sha256(flg.encode()).hexdigest())
        return ans == root

    def create_rsa_keys(self):
        """
        create rsa private and public keys.
        :return: rsa private and public keys
        """
        private_key_pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                         encryption_algorithm=serialization.NoEncryption())
        public_key = self.private_key.public_key()
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return private_key_pem, public_key_pem

    def sign_root(self, private_key_i):
        """
        sign the root of the tree using the private key.
        :param private_key_i: private key
        :return: signature
        """
        private_key = serialization.load_pem_private_key(private_key_i.encode(), password=None)
        message = str.encode(self.get_root())
        signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return base64.b64encode(signature).decode()

    @staticmethod
    def check_sign(key, signature, text):
        """
        check signature.
        :param key
        :param signature
        :param text
        :return: True/False depending if the check succeeded
        """
        key = serialization.load_pem_public_key(key.encode(), backend=default_backend())
        try:
            key.verify(base64.b64decode(signature), text.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except:
            return False


class SparseMerkleTree:

    def __init__(self):
        """
        init parameters for the SparseMerkleTree and initialize empty tree.
        """
        self.cache = {}
        self.zero_hashes = {256: '0'}
        self.__init_hashes()
        self.update_leaf('0' * 64, '0')

    def __init_hashes(self):
        """
        init the zero hashes
        """
        i = 1
        while i < 257:
            hashed = hashlib.sha256((self.zero_hashes[257 - i] * 2).encode()).hexdigest()
            self.zero_hashes[256 - i] = hashed
            i += 1

    def update_leaf(self, digest, value):
        """
        update leaf [with value of 0/1] and update the cache
        :param digest
        :param value
        """
        d_bin = self.input_to_binary(digest)
        self.cache[d_bin] = value
        while len(d_bin) > 0:
            d_bin = d_bin[:-1]
            default = self.zero_hashes[len(d_bin) + 1]
            left = self.cache[d_bin + '0'] if d_bin + '0' in self.cache else default
            right = self.cache[d_bin + '1'] if d_bin + '1' in self.cache else default
            self.cache[d_bin] = hashlib.sha256((left + right).encode()).hexdigest()

    def get_proof(self, digest):
        """
        create the proof, go over root to leaf [add value to the proof if they are not
        in the zero hash value dictionary]
        :param digest
        :return: proof of inclusion according to the assignment demands
        """
        d_bin = self.input_to_binary(digest)
        proof = self.get_root()
        flg = False
        while len(d_bin) > 0:
            default = self.zero_hashes[len(d_bin)]
            left = self.cache[d_bin[:-1] + '0'] if d_bin[:-1] + '0' in self.cache else default
            right = self.cache[d_bin[:-1] + '1'] if d_bin[:-1] + '1' in self.cache else default
            if left == '1' and right == '0':
                flg = True
            is_stored = left in set(self.zero_hashes.values()) and right in set(self.zero_hashes.values())
            if not is_stored:
                if flg:
                    if d_bin[len(d_bin) - 1] == '0':
                        proof += ' ' + right
                    else:
                        proof += ' ' + left
                else:
                    proof += ' ' + right + ' ' + left
            d_bin = d_bin[:-1]
        if proof == self.get_root():
            proof += ' ' + proof
        return proof

    @staticmethod
    def calc_zero_hashes_by_len(calc_len, value, dig_bin):
        for i in range(calc_len):
            dig_bin = dig_bin[:-1]
            value = hashlib.sha256((value + value).encode()).hexdigest()
        return value, dig_bin

    def check_proof(self, digest, val, proof):
        """
        check proof of inclusion by checking the length of the proof and
        if its small then 256 creates the zero hashes.
        :param digest
        :param val
        :param proof
        :return: True/False depending if we able to proof
        """
        dig_bin = self.input_to_binary(digest)
        value = val
        root = proof[0]
        rest_proof = proof[1:]
        if len(rest_proof) < 256:
            last_hash = rest_proof[0]
            rest_proof = rest_proof[1:]
            value, dig_bin = self.calc_zero_hashes_by_len(256 - len(rest_proof), value, dig_bin)
            if last_hash != value:
                return False
        for i in rest_proof:
            res = i + value if dig_bin[-1] == '1' else value + i
            value = hashlib.sha256(res.encode()).hexdigest()
            dig_bin = dig_bin[:-1]
        return value == root

    def get_root(self):
        """
        :return: the root of the tree.
        """
        return self.cache['']

    @staticmethod
    def input_to_binary(inp):
        """
        :param inp: input to make binary
        :return: binary string of the input
        """
        tmp = bin(int('1' + inp, 16))[3:]
        return tmp


def get_more_input(user_input):
    """
    create the keys for sections 6,7
    :param user_input: the privies user input
    :return: complete key
    """
    key = ' '.join(user_input[1:]) + '\n'
    inp = input()
    while inp:
        key += inp + '\n'
        inp = input()
    return key


def run_main():
    """
    run the main loop for the assignment.
    """
    merkle_tree = MerkleTree()
    sparse_merkle_tree = SparseMerkleTree()
    while True:
        user_input = input().split()
        len_input = len(user_input)
        if user_input[0] == '1' and len_input == 2:
            merkle_tree.new_leaf(user_input[1])
        elif user_input[0] == '2':
            print(merkle_tree.get_root())
        elif user_input[0] == '3' and len_input == 2:
            print(merkle_tree.create_proof(int(user_input[1])))
        elif user_input[0] == '4' and len_input >= 3:
            leaf = user_input[1]
            proof = ' '.join(user_input[2:])
            print(merkle_tree.check_proof(leaf, proof))
        elif user_input[0] == '5':
            private_key_pem, public_key_pem = merkle_tree.create_rsa_keys()
            print(private_key_pem.decode())
            print(public_key_pem.decode())
        elif user_input[0] == '6':
            private_key_i = get_more_input(user_input)
            print(merkle_tree.sign_root(private_key_i))
        elif user_input[0] == '7':
            public_key_i = get_more_input(user_input)
            sign_txt = input().split(' ')
            print(merkle_tree.check_sign(public_key_i, sign_txt[0], sign_txt[1]))
        elif user_input[0] == '8' and len_input == 2:
            sparse_merkle_tree.update_leaf(user_input[1], '1')
        elif user_input[0] == '9':
            print(sparse_merkle_tree.get_root())
        elif user_input[0] == '10' and len_input == 2:
            proof = sparse_merkle_tree.get_proof(user_input[1])
            print(proof)
        elif user_input[0] == '11' and len_input >= 3:
            print(sparse_merkle_tree.check_proof(user_input[1], user_input[2], user_input[3:]))
        else:
            print('')


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    run_main()
