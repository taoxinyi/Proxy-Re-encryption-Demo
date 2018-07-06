import os

from npre import bbs98
from npre import elliptic_curve as ec

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CA:
    """
    The CA that can be trusted
    Generate global parameters
    Distribute key pair for user
    """

    def __init__(self):
        self.pre = bbs98.PRE()
        self.__keypair_dict = {}

    def generate_keypair(self, user):
        sk = self.pre.gen_priv(dtype=bytes)
        pk = self.pre.priv2pub(sk)
        self.__keypair_dict[user.index] = {"pk": pk, "sk": sk}

    def get_public_key(self, user):
        user_index = user.index
        if user_index not in self.__keypair_dict.keys():
            self.generate_keypair(user)
        return self.__keypair_dict[user_index]["pk"]

    def get_secrete_key(self, user):
        user_index = user.index
        if user_index not in self.__keypair_dict.keys():
            self.generate_keypair(user)
        return self.__keypair_dict[user_index]["sk"]

    def get_re_key(self, delegator, delegatee):
        sk_delegator = self.get_secrete_key(delegator)
        sk_delegatee = self.get_secrete_key(delegatee)
        return self.pre.rekey(sk_delegator, sk_delegatee)

    def get_param(self):
        return ec.serialize(self.pre.g)

    def __str__(self):
        return self.__keypair_dict.__str__()


class Proxy():
    """
    The half-trustworthy Proxy(Server)
    Generate sym key(AES) on server to ensure security
    Store the encrypted message
    Take charge of re-encryption
    """

    def __init__(self, param):
        self.pre = bbs98.PRE(g=param)
        self.pk_list = []
        self.pre_aes_key = None
        self.pre_seed = None
        self.encrypted_data = None

    def register(self, user, ca):
        if user.index and user.index < len(self.pk_list):
            # This user already registered in Proxy
            return False
        else:
            # Assign index, request to CA Register in pk
            user.index = len(self.pk_list)
            ca.generate_keypair(user)
            self.pk_list.append(ca.get_public_key(user))
            return True

    def aes_encrypt(self, data, pre_seed, user):
        self.pre_seed = pre_seed
        key = os.urandom(32)
        iv = os.urandom(16)
        self.pre_aes_key = user.get_encrypted_aes_key(key + iv)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        self.encrypted_data = encryptor.update(data) + encryptor.finalize()
        return self.encrypted_data

    def aes_decrypt(self, aes_encrypted_data, aes_key):
        key = aes_key[0:32]
        iv = aes_key[32:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(aes_encrypted_data) + decryptor.finalize()

    def pre_reencrypt(self, rekey, pre_encrypted_data):
        return self.pre.reencrypt(rekey, pre_encrypted_data)


class Client():
    """
    The client
    Side to side encryption/decryption
    Generate random seed for stream cipher(CHACHA20)
    """

    def __init__(self, param, proxy, ca):
        self.pre = bbs98.PRE(g=param)
        self.index = None
        self.__random_seed = None
        self.__cipher = None
        self.__encryptor = None
        self.__decryptor = None
        # start registry
        proxy.register(self, ca)
        self.__sk = ca.get_secrete_key(self)
        self.__pk = ca.get_public_key(self)

    def generate_random_seed(self):
        key = os.urandom(32)
        nounce = os.urandom(16)
        self.__random_seed = key + nounce

    def get_random_seed(self):
        return self.__random_seed

    def init_chacha20(self, random_seed=None):
        if random_seed:
            self.__random_seed = random_seed
        else:
            self.generate_random_seed()
        algorithm = algorithms.ChaCha20(self.__random_seed[0:32], self.__random_seed[32:])
        self.__cipher = Cipher(algorithm, mode=None, backend=default_backend())
        self.__encryptor = self.__cipher.encryptor()
        self.__decryptor = self.__cipher.decryptor()

    def get_encryption_chacha20(self, data):
        return self.__encryptor.update(data)

    def get_decryption_chacha20(self, encrypted_data):
        return self.__decryptor.update(encrypted_data)

    def get_encrypted_seed(self):
        return self.__pre_encrypt(self.__random_seed)

    def get_decrypted_seed(self, encrypted_seed):
        return self.__pre_decrypt(encrypted_seed)

    def get_decrypted_aes_key(self, encrypted_aes_key):
        return self.__pre_decrypt(encrypted_aes_key)

    def get_encrypted_aes_key(self, aes_key):
        return self.__pre_encrypt(aes_key)

    def __pre_encrypt(self, data):
        return self.pre.encrypt(self.__pk, data)

    def __pre_decrypt(self, data):
        return self.pre.decrypt(self.__sk, data)

    def __str__(self):
        return (b"sk:" + self.__sk + b"pk:" + self.__pk).__str__()
