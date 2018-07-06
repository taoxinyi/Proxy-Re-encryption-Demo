import textwrap
from math import floor, ceil

from PRE_Candidate import CA, Proxy, Client


def pretty_print(name, content):
    name = name.ljust(35)
    wrapper = textwrap.TextWrapper(initial_indent=name, width=70,
                                   subsequent_indent=' ' * len(name))
    print(wrapper.fill(content) + '\n')


def print_send_to(left, right, content):
    left = left.ljust(5)
    right = right.rjust(5)

    total_len = len(left) + len(right) + len(content) + 1
    part_len = (70 - total_len) / 2
    print(left + '-' * floor(part_len) + content + '-' * ceil(part_len) + '>' + right + '\n')


def print_send_back(left, right, content):
    left = left.ljust(5)
    right = right.rjust(5)
    total_len = len(left) + len(right) + len(content) + 1
    part_len = (70 - total_len) / 2
    print(left + '<' + '-' * floor(part_len) + content + '-' * ceil(part_len) + right + '\n')


def print_middle(content):
    part_len = (70 - len(content)) / 2
    print('-' * floor(part_len) + content + '-' * ceil(part_len) + '\n')


"""---------------------------------------Initialize------------------------------------------"""
ca = CA()  # create CA
param = ca.get_param()  # generate global parameter
proxy = Proxy(param=param)  # create Proxy(Server) with parameter
a = Client(param=param, proxy=proxy, ca=ca)  # create user A with global parameter and Proxy & CA
b = Client(param=param, proxy=proxy, ca=ca)  # create user B with global parameter and Proxy & CA
print_send_to('A', 'CA', 'Request key pair')
print_send_back('A', 'CA', 'A key pair, global param')
print_send_to('B', 'CA', 'Request key pair')
print_send_back('B', 'CA', 'B key pair, global param')

"""---------------------------------------A restore on Proxy------------------------------------------"""

print_middle("A want to restore something on the Proxy")
msg = b"This is a demo"  # User A wants to send something to B
pretty_print("Plain msg sent from A:", msg.__str__())

a.init_chacha20()  # User A init chacha20,including generate random seed
seed_a = a.get_random_seed()
pretty_print("Seed from A:", seed_a.__str__())

msg_chacha20 = a.get_encryption_chacha20(msg)  # User A encrypt it with seed_a using CHACHA20
pretty_print("CHACHA20 msg sent from A:", msg_chacha20.__str__())

seed_pre_enc_a = a.get_encrypted_seed()  # User A encrypt seed using PRE with A's public key
pretty_print("PRE encrpyted seed from A:", seed_pre_enc_a.__str__())
print_send_to('A', 'PROXY', '(CHACHA20 msg,PRE encrypted seed)')

aes_enc_msg = \
    proxy.aes_encrypt(msg_chacha20, seed_pre_enc_a, a)  # PROXY generate random AES key and encrypt CHACHA20 message
pretty_print("AES encrypted data on Proxy:", aes_enc_msg.__str__())
print_middle("The data is safely restored on the Proxy")

"""---------------------------------------A download from Proxy------------------------------------------"""

print_middle("Of course A can download and see it at anytime")
print_send_to('A', 'PROXY', 'Request CHACHA 20 msg')
print_send_back('A', 'PROXY', '(PRE_enc_seed, PRE_enc_aes_key), Request plain aes_key')

aes_key_a = a.get_decrypted_aes_key(proxy.pre_aes_key)
pretty_print("Plain AES key re-decrypted by A:", aes_key_a.__str__())
print_send_to('a', 'Proxy', 'plain aes_key')  # A send plain aes key to Proxy for decryption

msg_chacha20_a = proxy.aes_decrypt(proxy.encrypted_data, aes_key_a)  # Proxy decrypted msg using AES and send back to B
pretty_print("CHACHA20 msg decrypted by Proxy:", msg_chacha20_a.__str__())
print_send_back('A', 'Proxy', 'CHACHA 20 msg')  # Proxy send CHACHA20 msg to A after decryption

pre_dec_seed_a = a.get_decrypted_seed(proxy.pre_seed)  # A decrypted pre_seed for plain seed
pretty_print("Seed PRE decrypted by A:", pre_dec_seed_a.__str__())
a.init_chacha20(pre_dec_seed_a)  # A initialize CHACHA20 by that seed
msg_a = a.get_encryption_chacha20(msg_chacha20_a)
pretty_print("Plain msg received from A:", msg_a.__str__())
print_middle("Now A successfully received the own correct data")

"""---------------------------------------A share it to B------------------------------------------"""
print_middle("A want to send that to B")

print_send_to('A', 'CA', 'Request Re-encryption Key with B')  # A request rkey with B from CA

rkey = ca.get_re_key(a, b)  # CA cacluate re-encryption key from A to B,send it to A
pretty_print("Re-encryption Key A->B:", rkey.__str__())

print_send_back('A', 'CA', 'Re-encryption Key A->B')  # CA send re-encryption key to A after calculation
print_send_to('A', 'Proxy', 'Re-encryption A->B')  # A send re-encryption key to Proxy

pre_re_enc_seed_b = proxy.pre_reencrypt(rkey, seed_pre_enc_a)  # Proxy calculate re-encrypted seed for B
pretty_print("Re-encrypted seed:", pre_re_enc_seed_b.__str__())

pre_re_enc_aes_key_b = proxy.pre_reencrypt(rkey, proxy.pre_aes_key)  # Proxy calculate re-encrypted aes key for B
pretty_print("Re-encrypted AES key:", pre_re_enc_aes_key_b.__str__())

"""---------------------------------------B download it from Proxy------------------------------------------"""

print_send_back('B', 'Proxy',
                '(re_enc_seed, re_enc_aes_key), Request plain aes_key')  # CA send re-encryption key to A

aes_key_b = b.get_decrypted_aes_key(pre_re_enc_aes_key_b)  # B re-decrypted pre_re_enc_aes_key, send back to Proxy
pretty_print("Plain AES key re-decrypted by B:", aes_key_b.__str__())
print_send_to('B', 'Proxy', 'plain aes_key')  # B send plain aes key to Proxy for decryption

msg_chacha20_b = proxy.aes_decrypt(proxy.encrypted_data, aes_key_b)  # Proxy decrypted msg using AES and send back to B
pretty_print("CHACHA20 msg decrypted by Proxy:", msg_chacha20_b.__str__())
print_send_back('B', 'Proxy', 'CHACHA 20 msg')  # Proxy  send CHACHA20 msg to B after decryption

pre_dec_seed_b = b.get_decrypted_seed(pre_re_enc_seed_b)  # B re-decrypted pre_re_enc_seed for plain seed
pretty_print("Seed re-decrypted by B:", pre_dec_seed_b.__str__())
b.init_chacha20(pre_dec_seed_b)  # B initialize CHACHA20 by that seed
msg_b = b.get_encryption_chacha20(msg_chacha20_b)
pretty_print("Plain msg received from B:", msg_b.__str__())
print_middle("Now B successfully received the correct data from A")

assert msg == msg_a
assert msg == msg_b
