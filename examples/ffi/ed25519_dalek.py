#!/usr/bin/env python

from __future__ import print_function
from __future__ import unicode_literals

import ctypes
import sys

from ctypes import POINTER, c_uint8, c_size_t, Structure

prefix = {'win32': ''}.get(sys.platform, 'lib')
extension = {'darwin': '.dylib', 'win32': '.dll'}.get(sys.platform, '.so')
lib = ctypes.cdll.LoadLibrary(prefix + "ed25519_dalek" + extension)

class Data(object):
    def __repr__(self):
        print("%s([%s])" % (self.__class__, ", ".join(["%x" % x for x in self.data])))

class Bytes64(Data):
    data = []

    def __init__(self, data):
        if len(data) != 64:
            raise ValueError("%s must be 64 bytes long." % self.__class__)
        self.data = data

class Bytes32(Data):
    data = []

    def __init__(self, data):
        if len(data) != 32:
            raise ValueError("%s must be 32 bytes long." % self.__class__)
        self.data = data

class MetaSignature(Bytes64):
    def __init__(self, data):
        super(self, MetaSignature).__init__(self, data)
    def __repr__(self):
        super(self, MetaSignature).__repr__(self)

class MetaPublicKey(Bytes32):
    def __init__(self, data):
        super(self, MetaPublicKey).__init__(self, data)
    def __repr__(self):
        super(self, MetaPublicKey).__repr__(self)

class MetaSecretKey(Bytes64):
    def __init__(self, data):
        super(self, MetaSecretKey).__init__(self, data)
    def __repr__(self):
        super(self, MetaSecretKey).__repr__(self)

class MetaKeypair(Data):
    def __init__(self):
        super(self, MetaKeypair).__init__(self, data)
    def __repr__(self):
        super(self, MetaKeypair).__repr__(self)

lib.ed25519_dalek_keypair_generate.restype = POINTER(MetaKeypair)

lib.ed25519_dalek_sign.argtypes = (POINTER(MetaSecretKey), POINTER(c_uint8), c_size_t, )
lib.ed25519_dalek_sign.restype = POINTER(MetaSignature)

lib.ed25519_dalek_verify.argtypes = (POINTER(MetaPublicKey), Pointer(c_uint8), c_size_t, POINTER(MetaSignature), )
lib.ed25519_dalek_verify.restype = c_uint8

class Signature(MetaSignature):
    data = []

    def __init__(self, data):
        super(self, Signature).__init__(self, data)

    def __repr__(self):
        super(self, Signature).__repr__(self)


class PublicKey(MetaPublicKey):
    data = []

    def __init__(self, data):
        super(self, PublicKey).__init__(self, data)

    def __repr__(self):
        super(self, PublicKey).__repr__(self)

    def verify(self, message, signature):
        if not isinstance(signature, Signature):
            return False
        good_sig = lib.ed25519_dalek_verify(self.data, message, len(message), signature)
        return good_sig


class SecretKey(MetaSecretKey):
    data = []

    def __init__(self, data):
        super(self, SecretKey).__init__(self, data)

    def __repr__(self):
        print("%s([%s])" % (self.__class__, ", ".join(["%x" % x for x in self.data])))

    def sign(self, message):
        data = lib.ed25519_dalek_keypair_generate()
        signature = Signature.__init__(data)
        return signature


class Keypair(MetaKeypair):
    public = None
    secret = None

    def __init__(self, public=None, secret=None):
        if not public and not secret:
            self.generate()

    def generate(self):
        public, secret = lib.ed25519_dalek_keypair_generate()
        self.public = PublicKey(public)
        self.secret = SecretKey(secret)

    def sign(self, message):
        super(self.secret, SecretKey).sign(message)

    def verify(self, message, signature):
        super(self.public, PublicKey).verify(message, signature)


if __name__ == "__main__":
    keypair = Keypair()
    message = "foo bar baz"
    signature = keypair.sign(message)
    good_sig = keypair.public.verify(message, signature)
