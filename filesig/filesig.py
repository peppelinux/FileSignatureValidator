#!/usr/bin/env python3

import io
import json
import re
import os
import subprocess
import tempfile

from collections import OrderedDict


proc_pdfsig = subprocess.Popen('pdfsig -v',
                               shell=True,
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE)
stdout, stderr = proc_pdfsig.communicate()
if stdout:
    print(stdout.decode())
    print(stderr.decode())
    raise Exception(('pdfsig is not installed.'
                     'Please install poppler or poppler-utils'))

proc_openssl = subprocess.Popen('openssl version',
                                shell=True,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE)
stdout, stderr = proc_openssl.communicate()
if stderr:
    print(stdout.decode())
    print(stderr.decode())
    raise Exception(('openssl is not installed.'
                     'Please install it'))

_ATTRIBUTES = ['Signature Type',
               'Signature Validation',
               'Signer Certificate Common Name',
               'Signer full Distinguished Name',
               'Signing Hash Algorithm',
               'Signing Time']

def get_pdf_signatures(fname, only_valids=False):
    try:
        raw_result = subprocess.check_output(['pdfsig', fname],
                                             stderr=subprocess.STDOUT).decode('utf-8')
    except:
        return []

    result = re.split('Signature #[0-9]+:\n', raw_result)

    pdf_name = result[0]
    signatures = result[1:]
    if only_valids:
        filter_out = "Signature Validation: Signature has not yet been verified"
        valid_signatures = [i.strip() for i in signatures if filter_out not in i]
    else:
        valid_signatures = [i.strip() for i in signatures]

    re.search('Signature #(?P<n>[0-9]+):(?P<content>[\t\n\w\s\:\-\_\.A-Za-z\,\=\[\]\(\)]*)',
              raw_result).groups()

    cleaned_signatures = []
    for i in valid_signatures:
        d = OrderedDict()
        splitted = i.split('\n')
        for s in splitted:
            cleaned_s = re.sub('^[\s\-]+', '', s)
            splitc = cleaned_s.partition(':')
            k, v = splitc[0].strip(), splitc[2].strip()
            if k in _ATTRIBUTES:
                d[k] = v
        cleaned_signatures.append(d)
    return cleaned_signatures


def get_p7m_signatures(fname, only_valids=False):
    """
    """
    d = OrderedDict()
    #verification_cmd = "openssl smime -verify -noverify -in {} -inform DER -out /dev/null 2>&1".format(fname)
    #pkcs7_cmd = 'openssl pkcs7 -print -text -inform der -in {}'.format(fname)
    try:
        verification_result = subprocess.check_output(["openssl",
                                                       "smime",
                                                       "-verify",
                                                       "-noverify",
                                                       "-in",
                                                       fname,
                                                       "-inform",
                                                       "DER",
                                                       "-out",
                                                       "/dev/null",
                                                       "2>&1"],
                                                      stderr=subprocess.STDOUT).decode('utf-8')
    except:
        return []

    check_validity = 'successful' in verification_result
    if check_validity:
        d['Signature Validation'] = 'Signature is Valid.'
    elif only_valids and not check_validity:
        d['Signature Validation'] = 'Signature has not yet been verified'
        return [d]

    pkcs_result = subprocess.check_output(["openssl",
                                           "pkcs7",
                                           "-print",
                                           "-text",
                                           "-inform",
                                           "der",
                                           "-in",
                                           fname],
                                          stderr=subprocess.STDOUT).decode('utf-8')
    pkcs_subject, pkcs_date = (re.search('subject:[\s]*(?P<subject>.*)', pkcs_result),
                               re.search('UTCTIME:(?P<date_signed>.*)', pkcs_result))
    if pkcs_subject:
        d["Signer full Distinguished Name"] = pkcs_subject.groupdict()['subject']
    if pkcs_date:
        d["Signing Time"] = pkcs_date.groupdict()['date_signed']

    return [d]


def get_signatures(fname, type='pdf', only_valids=False):
    if type == 'pdf':
        func_name = get_pdf_signatures
    elif type == 'p7m':
        func_name = get_p7m_signatures
    else:
        raise Exception('File format {} not supported'.format(args.t))

    tfile = fname
    # check if the file is a string (path to it) or a buffered io objects (with or open())
    #if isinstance(fname, io.BufferedReader):
    if not isinstance(fname, str):
        temp_file = tempfile.NamedTemporaryFile()
        temp_file.write(fname.read())
        temp_file.flush()
        tfile = temp_file.name

    return func_name(tfile, only_valids)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', required=False, action='store_true',
                        help="returns onvly valids signs")
    parser.add_argument('-f', required=True,
                        help="filename to inspect")
    parser.add_argument('-t', required=False, default='pdf',
                        help="file format: pdf or p7m")
    args = parser.parse_args()

    print(json.dumps(get_signatures(args.f,
                                    type=args.t,
                                    only_valids=args.v), indent=2))
