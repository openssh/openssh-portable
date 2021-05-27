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
    "oqs-default-sha256",
    "ecdh-nistp256-oqs-default-sha256",
    "frodokem-640-aes-sha256",
    "ecdh-nistp256-frodokem-640-aes-sha256",
    "frodokem-976-aes-sha384",
    "ecdh-nistp384-frodokem-976-aes-sha384",
    "frodokem-1344-aes-sha512",
    "ecdh-nistp521-frodokem-1344-aes-sha512",
    "frodokem-640-shake-sha256",
    "ecdh-nistp256-frodokem-640-shake-sha256",
    "frodokem-976-shake-sha384",
    "ecdh-nistp384-frodokem-976-shake-sha384",
    "frodokem-1344-shake-sha512",
    "ecdh-nistp521-frodokem-1344-shake-sha512",
    "sidh-p434-sha256",
    "ecdh-nistp256-sidh-p434-sha256",
    "sidh-p434-compressed-sha256",
    "ecdh-nistp256-sidh-p434-compressed-sha256",
    "sidh-p610-sha256",
    "ecdh-nistp384-sidh-p610-sha256",
    "sidh-p610-compressed-sha256",
    "ecdh-nistp384-sidh-p610-compressed-sha256",
    "sidh-p751-sha256",
    "ecdh-nistp521-sidh-p751-sha256",
    "sidh-p751-compressed-sha256",
    "ecdh-nistp521-sidh-p751-compressed-sha256",
    "sike-p434-sha256",
    "ecdh-nistp256-sike-p434-sha256",
    "sike-p434-compressed-sha256",
    "ecdh-nistp256-sike-p434-compressed-sha256",
    "sike-p610-sha256",
    "ecdh-nistp384-sike-p610-sha256",
    "sike-p610-compressed-sha256",
    "ecdh-nistp384-sike-p610-compressed-sha256",
    "sike-p751-sha256",
    "ecdh-nistp521-sike-p751-sha256",
    "sike-p751-compressed-sha256",
    "ecdh-nistp521-sike-p751-compressed-sha256",
    "saber-lightsaber-sha256",
    "ecdh-nistp256-saber-lightsaber-sha256",
    "saber-saber-sha384",
    "ecdh-nistp384-saber-saber-sha384",
    "saber-firesaber-sha512",
    "ecdh-nistp521-saber-firesaber-sha512",
    "kyber-512-sha256",
    "ecdh-nistp256-kyber-512-sha256",
    "kyber-768-sha384",
    "ecdh-nistp384-kyber-768-sha384",
    "kyber-1024-sha512",
    "ecdh-nistp521-kyber-1024-sha512",
    "kyber-512-90s-sha256",
    "ecdh-nistp256-kyber-512-90s-sha256",
    "kyber-768-90s-sha384",
    "ecdh-nistp384-kyber-768-90s-sha384",
    "kyber-1024-90s-sha512",
    "ecdh-nistp521-kyber-1024-90s-sha512",
    "bike1-l1-cpa-sha512",
    "ecdh-nistp256-bike1-l1-cpa-sha512",
    "bike1-l1-fo-sha512",
    "ecdh-nistp256-bike1-l1-fo-sha512",
    "bike1-l3-cpa-sha512",
    "ecdh-nistp384-bike1-l3-cpa-sha512",
    "bike1-l3-fo-sha512",
    "ecdh-nistp384-bike1-l3-fo-sha512",
    "ntru-hps2048509-sha512",
    "ecdh-nistp256-ntru-hps2048509-sha512",
    "ntru-hps2048677-sha512",
    "ecdh-nistp384-ntru-hps2048677-sha512",
    "ntru-hrss701-sha512",
    "ecdh-nistp384-ntru-hrss701-sha512",
    "ntru-hps4096821-sha512",
    "ecdh-nistp521-ntru-hps4096821-sha512",
    "classic-mceliece-348864-sha256",
    "ecdh-nistp256-classic-mceliece-348864-sha256",
    "classic-mceliece-348864f-sha256",
    "ecdh-nistp256-classic-mceliece-348864f-sha256",
    "classic-mceliece-460896-sha512",
    "ecdh-nistp384-classic-mceliece-460896-sha512",
    "classic-mceliece-460896f-sha512",
    "ecdh-nistp384-classic-mceliece-460896f-sha512",
    "classic-mceliece-6688128-sha512",
    "ecdh-nistp521-classic-mceliece-6688128-sha512",
    "classic-mceliece-6688128f-sha512",
    "ecdh-nistp521-classic-mceliece-6688128f-sha512",
    "classic-mceliece-6960119-sha512",
    "ecdh-nistp521-classic-mceliece-6960119-sha512",
    "classic-mceliece-6960119f-sha512",
    "ecdh-nistp521-classic-mceliece-6960119f-sha512",
    "classic-mceliece-8192128-sha512",
    "ecdh-nistp521-classic-mceliece-8192128-sha512",
    "classic-mceliece-8192128f-sha512",
    "ecdh-nistp521-classic-mceliece-8192128f-sha512",
    "hqc-128-sha256",
    "ecdh-nistp256-hqc-128-sha256",
    "hqc-192-sha384",
    "ecdh-nistp384-hqc-192-sha384",
    "hqc-256-sha512",
    "ecdh-nistp521-hqc-256-sha512",
    "ntruprime-ntrulpr653-sha256",
    "ecdh-nistp256-ntruprime-ntrulpr653-sha256",
    "ntruprime-sntrup653-sha256",
    "ecdh-nistp256-ntruprime-sntrup653-sha256",
    "ntruprime-ntrulpr761-sha384",
    "ecdh-nistp384-ntruprime-ntrulpr761-sha384",
    "ntruprime-sntrup761-sha384",
    "ecdh-nistp384-ntruprime-sntrup761-sha384",
    "ntruprime-ntrulpr857-sha384",
    "ecdh-nistp384-ntruprime-ntrulpr857-sha384",
    "ntruprime-sntrup857-sha384",
    "ecdh-nistp384-ntruprime-sntrup857-sha384",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_END
]

sigs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
    "ssh-oqsdefault",
    "ssh-rsa3072-oqsdefault",
    "ssh-ecdsa-nistp256-oqsdefault",
    "ssh-falcon512",
    "ssh-rsa3072-falcon512",
    "ssh-ecdsa-nistp256-falcon512",
    "ssh-falcon1024",
    "ssh-ecdsa-nistp521-falcon1024",
    "ssh-dilithium3",
    "ssh-ecdsa-nistp384-dilithium3",
    "ssh-dilithium2aes",
    "ssh-rsa3072-dilithium2aes",
    "ssh-ecdsa-nistp256-dilithium2aes",
    "ssh-dilithium5aes",
    "ssh-ecdsa-nistp521-dilithium5aes",
    "ssh-picnicL1full",
    "ssh-rsa3072-picnicL1full",
    "ssh-ecdsa-nistp256-picnicL1full",
    "ssh-picnicL3FS",
    "ssh-ecdsa-nistp384-picnicL3FS",
    "ssh-sphincsharaka128fsimple",
    "ssh-rsa3072-sphincsharaka128fsimple",
    "ssh-ecdsa-nistp256-sphincsharaka128fsimple",
    "ssh-sphincsharaka192frobust",
    "ssh-ecdsa-nistp384-sphincsharaka192frobust",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

def do_handshake(ssh, sshd, test_sig, test_kex):
    sshd_process = subprocess.Popen([sshd, 
                                    '-f', os.path.abspath('regress/sshd_config'),
                                    "-o", "KexAlgorithms={}".format(test_kex),
                                    "-o", "HostKeyAlgorithms={}".format(test_sig),
                                    '-D'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)

    # sshd should locally (hopefully?) start within 1 second. If activating Rainbow, at least an order of magnitude more delay must be considered.
    time.sleep(1)

    # Try to connect to it with the client
    ssh_process = subprocess.run([ssh,
                                 '-F', os.path.abspath('regress/ssh_config'),
                                 "-o", "HostKeyAlgorithms={}".format(test_sig),
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

