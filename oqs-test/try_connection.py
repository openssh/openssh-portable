# This script simply picks a random OQS or non-OQS key-exchange
# and signature algorithm, and checks whether the stock BoringSSL
# client and server can establish a handshake with the choices.

import os
import random
import subprocess
import time
import sys

# Requires make tests LTESTS="" to be run first

kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_START
    "frodokem-640-aes-sha256",
    "ecdh-nistp256-frodokem-640-aesr2-sha256@openquantumsafe.org",
    "frodokem-976-aes-sha384",
    "ecdh-nistp384-frodokem-976-aesr2-sha384@openquantumsafe.org",
    "frodokem-1344-aes-sha512",
    "ecdh-nistp521-frodokem-1344-aesr2-sha512@openquantumsafe.org",
    "frodokem-640-shake-sha256",
    "ecdh-nistp256-frodokem-640-shaker2-sha256@openquantumsafe.org",
    "frodokem-976-shake-sha384",
    "ecdh-nistp384-frodokem-976-shaker2-sha384@openquantumsafe.org",
    "frodokem-1344-shake-sha512",
    "ecdh-nistp521-frodokem-1344-shaker2-sha512@openquantumsafe.org",
    "kyber-512-sha256",
    "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org",
    "kyber-768-sha384",
    "ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org",
    "kyber-1024-sha512",
    "ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org",
    "bike-l1-sha512",
    "ecdh-nistp256-bike-l1r3-sha512@openquantumsafe.org",
    "bike-l3-sha512",
    "ecdh-nistp384-bike-l3r3-sha512@openquantumsafe.org",
    "classic-mceliece-348864-sha256",
    "ecdh-nistp256-classic-mceliece-348864r4-sha256@openquantumsafe.org",
    "classic-mceliece-348864f-sha256",
    "ecdh-nistp256-classic-mceliece-348864fr4-sha256@openquantumsafe.org",
    "classic-mceliece-460896-sha512",
    "ecdh-nistp384-classic-mceliece-460896r4-sha512@openquantumsafe.org",
    "classic-mceliece-460896f-sha512",
    "ecdh-nistp384-classic-mceliece-460896fr4-sha512@openquantumsafe.org",
    "classic-mceliece-6688128-sha512",
    "ecdh-nistp521-classic-mceliece-6688128r4-sha512@openquantumsafe.org",
    "classic-mceliece-6688128f-sha512",
    "ecdh-nistp521-classic-mceliece-6688128fr4-sha512@openquantumsafe.org",
    "classic-mceliece-6960119-sha512",
    "ecdh-nistp521-classic-mceliece-6960119r4-sha512@openquantumsafe.org",
    "classic-mceliece-6960119f-sha512",
    "ecdh-nistp521-classic-mceliece-6960119fr4-sha512@openquantumsafe.org",
    "classic-mceliece-8192128-sha512",
    "ecdh-nistp521-classic-mceliece-8192128r4-sha512@openquantumsafe.org",
    "classic-mceliece-8192128f-sha512",
    "ecdh-nistp521-classic-mceliece-8192128fr4-sha512@openquantumsafe.org",
    "hqc-128-sha256",
    "ecdh-nistp256-hqc-128r3-sha256@openquantumsafe.org",
    "hqc-192-sha384",
    "ecdh-nistp384-hqc-192r3-sha384@openquantumsafe.org",
    "hqc-256-sha512",
    "ecdh-nistp521-hqc-256r3-sha512@openquantumsafe.org",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_END
]

sigs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
    "ssh-falcon512",
    "ssh-rsa3072-falcon512",
    "ssh-ecdsa-nistp256-falcon512",
    "ssh-falcon1024",
    "ssh-ecdsa-nistp521-falcon1024",
    "ssh-dilithium2",
    "ssh-rsa3072-dilithium2",
    "ssh-ecdsa-nistp256-dilithium2",
    "ssh-dilithium3",
    "ssh-ecdsa-nistp384-dilithium3",
    "ssh-dilithium5",
    "ssh-ecdsa-nistp521-dilithium5",
    "ssh-sphincssha2128fsimple",
    "ssh-rsa3072-sphincssha2128fsimple",
    "ssh-ecdsa-nistp256-sphincssha2128fsimple",
    "ssh-sphincssha2256fsimple",
    "ssh-ecdsa-nistp521-sphincssha2256fsimple",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

def do_handshake(ssh, sshd, test_sig, test_kex):
    sshd_process = subprocess.Popen([sshd,
                                    '-f', os.path.abspath('regress/sshd_config'),
                                    "-o", "KexAlgorithms={}".format(test_kex),
                                    "-o", "HostKeyAlgorithms={}".format(test_sig),
                                    "-o", "PubkeyAcceptedKeyTypes={}".format(test_sig),
                                    "-h", os.path.abspath("regress/host.{}".format(test_sig)),
                                    '-D'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)

    # sshd should locally (hopefully?) start within 1 second.
    time.sleep(1)

    # Try to connect to it with the client
    ssh_process = subprocess.run([ssh,
                                 '-F', os.path.abspath('regress/ssh_config'),
                                 "-o", "HostKeyAlgorithms={}".format(test_sig),
                                 "-o", "PubkeyAcceptedKeyTypes={}".format(test_sig),
                                 "-o", "PasswordAuthentication=no",
                                 "-i", os.path.abspath("regress/{}".format(test_sig)),
                                 'somehost', 'true'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
    ssh_stdout = ssh_process.stdout.decode()
    sshd_process.kill()

    #print("SSHD: %s\n\n" % (sshd_process.stdout.read().decode()))
    assert "debug1: kex: algorithm: {}".format(test_kex) in ssh_stdout, ssh_stdout
    assert "debug1: kex: host key algorithm: {}".format(test_sig) in ssh_stdout, ssh_stdout
    assert ssh_process.returncode == 0, ssh_stdout

    print("Success! Key Exchange Algorithm: {}. Signature Algorithm: {}.".format(test_kex, test_sig))

def try_handshake(ssh, sshd, dorandom="random"):
    if dorandom!="random":
       for test_kex in kexs:
           for test_sig in sigs:
               if dorandom=="doall" or (dorandom=="doone" and (test_kex==kexs[0] or test_sig==sigs[0])):
                   do_handshake(ssh, sshd, test_sig, test_kex)
    else:
       test_sig = random.choice(sigs)
       test_kex = random.choice(kexs)
       do_handshake(ssh, sshd, test_sig, test_kex)

if __name__ == '__main__':
    if len(sys.argv)==1:
        try_handshake(os.path.abspath('ssh'), os.path.abspath('sshd'))
    else:
        try_handshake(os.path.abspath('ssh'), os.path.abspath('sshd'), dorandom=sys.argv[1])

