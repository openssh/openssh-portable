# This script simply picks a random OQS or non-OQS key-exchange
# and signature algorithm, and checks whether the stock BoringSSL
# client and server can establish a handshake with the choices.

import os
import random
import subprocess
import time

# Requires make tests LTESTS="" to be run first

kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_START
    "oqs-default-sha256",
    "ecdh-nistp256-oqs-default-sha256",
    "frodokem-640-aes-sha256",
    "ecdh-nistp256-frodokem-640-aes-sha256",
    "frodokem-976-aes-sha384",
    "ecdh-nistp384-frodokem-976-aes-sha384",
    "frodokem-1344-aes-sha512",
    "ecdh-nistp521-frodokem-1344-aes-sha512",
    "sike-p434-sha256",
    "ecdh-nistp256-sike-p434-sha256",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_END
]

sigs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
    "ssh-oqsdefault",
    "ssh-rsa3072-oqsdefault",
    "ssh-ecdsa-nistp256-oqsdefault",
    "ssh-dilithium2",
    "ssh-rsa3072-dilithium2",
    "ssh-ecdsa-nistp256-dilithium2",
    "ssh-dilithium3",
    "ssh-ecdsa-nistp384-dilithium3",
    "ssh-dilithium5",
    "ssh-ecdsa-nistp521-dilithium5",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

def try_handshake(ssh, sshd):
    random_sig = random.choice(sigs)
    random_kex = random.choice(kexs)

    sshd_process = subprocess.Popen([sshd,
                                    '-f', os.path.abspath('regress/sshd_config'),
                                    "-o", "KexAlgorithms={}".format(random_kex),
                                    "-o", "HostKeyAlgorithms={}".format(random_sig),
                                    '-D'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)

    # sshd should (hopefully?) start in 10 seconds.
    time.sleep(10)

    # Try to connect to it with the client
    ssh_process = subprocess.run([ssh,
                                 '-F', os.path.abspath('regress/ssh_config'),
                                 "-o", "HostKeyAlgorithms={}".format(random_sig),
                                 'somehost', 'true'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
    ssh_stdout = ssh_process.stdout.decode()
    sshd_process.kill()

    assert "debug1: kex: algorithm: {}".format(random_kex) in ssh_stdout, ssh_stdout
    assert "debug1: kex: host key algorithm: {}".format(random_sig) in ssh_stdout, ssh_stdout
    assert ssh_process.returncode == 0, ssh_stdout

    print("Success! Key Exchange Algorithm: {}. Signature Algorithm: {}.".format(random_kex, random_sig))

if __name__ == '__main__':
    try_handshake(os.path.abspath('ssh'), os.path.abspath('sshd'))
