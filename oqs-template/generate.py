#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
import yaml

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def populate(filename, config, delimiter):
    fragments = glob.glob(os.path.join('oqs-template', filename, '*.fragment'))
    contents = file_get_contents(filename)

    for fragment in fragments:
        identifier_base = os.path.splitext(os.path.basename(fragment))[0]

        if filename == 'README.md':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START -->'.format(delimiter, identifier_base.upper())
        elif filename == 'myproposal.h':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START */ \\'.format(delimiter, identifier_base.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier_base.upper())

        if filename == 'myproposal.h':
            identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END */'.format(delimiter, identifier_base.upper())
        else:
            identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier_base.upper())

        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]

        contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble

    file_put_contents(filename, contents)

def load_config(include_disabled_algs=False):
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    if not include_disabled_algs:
        config['sigs'] = [sig for sig in config['sigs'] if 'enable' in sig.keys() and sig['enable']]

        # enable if single KEXs are to be en/disabled:
        #config['kexs'] = [kex for kex in config['kexs'] if 'enable' in kex.keys() and kex['enable']]

    return config

config = load_config()

# kexs
populate('kex.c', config, '/////')
populate('kexgen.c', config, '/////')
populate('kexoqs.c', config, '/////')
populate('kexoqsecdh.c', config, '/////')
populate('monitor.c', config, '/////')
populate('sshd.c', config, '/////')
populate('sshconnect2.c', config, '/////')
populate('ssh_api.c', config, '/////')
populate('kex.h', config, '/////')
populate('myproposal.h', config, '/*///')

# sigs
populate('readconf.c', config, '/////')
populate('servconf.c', config, '/////')
populate('ssh-add.c', config, '/////')
populate('ssh-keygen.c', config, '/////')
populate('ssh-oqs.c', config, '/////')
populate('pathnames.h', config, '/////')
populate('sk-api.h', config, '/////')
populate('sshkey.c', config, '/////')
populate('ssh-keysign.c', config, '/////')
populate('ssh.c', config, '/////')
populate('sshkey.h', config, '/////')
populate('oqs-utils.h', config, '/////')
populate('oqs-utils.c', config, '/////')
populate('ssh-rsa.c', config, '/////')
populate('regress/keygen-comment.sh', config, '#####')

# both
populate('ssh-keyscan.c', config, '/////')
populate('oqs-test/try_connection.py', config, '#####')

config = load_config(include_disabled_algs=True)
populate('README.md', config, '<!---')

