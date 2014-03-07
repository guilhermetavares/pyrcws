# coding: utf-8
import sha
from M2Crypto import X509
from base64 import b64encode


class X509FingerprintKeypairReference:
    def __init__(self, fingerprint, algorithm='sha1'):
        self.fingerprint = self.normalize_fingerprint(fingerprint)
        self.algorithm = algorithm

    def getFingerprint(self):
        return self.fingerprint

    def getAlgorithm(self):
        return self.algorithm

    def __hash__(self):
        return self.fingerprint.__hash__() ^ self.algorithm.__hash__()

    def __eq__(self, other):
        return self.fingerprint == other.getFingerprint() and self.algorithm == other.getAlgorithm()

    def normalize_fingerprint(self, fingerprint):
        return fingerprint.lower()


class X509SubjectKeyIdentifierKeypairReference:
    def __init__(self, ski):
        self.ski = self.normalize_ski(ski)

    def getSubjectKeyIdentifier(self):
        return self.ski

    def normalize_ski(self, ski):
        return ski.lower()

    def __hash__(self):
        return self.ski.__hash__()

    def __eq__(self, other):
        return self.ski == other.getSubjectKeyIdentifier()


class X509PemFileCertificate:
    def __init__(self, pem_file_name):
        self.x509_cert = X509.load_cert(pem_file_name, X509.FORMAT_PEM)
        self.x509_issuer_serial = self.build_x509_issuer_serial(self.x509_cert)
        self.md5fingerprint = X509FingerprintKeypairReference(
            self.x509_cert.get_fingerprint('md5'), 'md5')
        self.sha1fingerprint = X509FingerprintKeypairReference(
            self.x509_cert.get_fingerprint('sha1'), 'sha1')
        self.subjectKeyIdentifier = X509SubjectKeyIdentifierKeypairReference(
            self.x509_cert.get_ext(
                'subjectKeyIdentifier').get_value().replace(':', ''))
        sha1 = sha.new()
        sha1.update(self.x509_cert.get_pubkey().as_der())
        sha1_identifier = sha1.digest()
        self.sha1SubjectKeyIdentifier = X509SubjectKeyIdentifierKeypairReference(sha1_identifier.encode('hex'))
        rfc3280_identifier = chr(0x40 | (ord(sha1_identifier[-8]) & 0xf)) + sha1_identifier[-7:]
        self.rfc3280SubjectKeyIdentifier = X509SubjectKeyIdentifierKeypairReference(rfc3280_identifier.encode('hex'))

    def getX509IssuerSerial(self):
        return self.x509_issuer_serial

    def getMD5Fingerprint(self):
        return self.md5fingerprint

    def getSHA1Fingerprint(self):
        return self.sha1fingerprint

    def getSubjectKeyIdentifier(self):
        return self.subjectKeyIdentifier

    def getCertificateText(self):
        return b64encode(self.x509_cert.as_der())

    def getIssuer(self):
        return self.x509_issuer_serial.getIssuer()

    def getSerial(self):
        return self.x509_issuer_serial.getSerial()

    def getRsaPublicKey(self):
        return self.x509_cert.get_pubkey().get_rsa()

    def getEvpPublicKey(self):
        return self.x509_cert.get_pubkey()

    def getReferences(self):
        return [self.x509_issuer_serial, self.md5fingerprint, self.sha1fingerprint, self.subjectKeyIdentifier, self.sha1SubjectKeyIdentifier, self.rfc3280SubjectKeyIdentifier]

    def build_x509_issuer_serial(self, x509_cert):
        x509_cert_issuer = x509_cert.get_issuer()
        issuer_name_list = []
        x509_cert_issuer.CN and issuer_name_list.append("CN=%s" % x509_cert_issuer.CN)
        x509_cert_issuer.OU and issuer_name_list.append("OU=%s" % x509_cert_issuer.OU)
        x509_cert_issuer.O and issuer_name_list.append("O=%s" % x509_cert_issuer.O)
        x509_cert_issuer.L and issuer_name_list.append("L=%s" % x509_cert_issuer.L)
        x509_cert_issuer.ST and issuer_name_list.append("ST=%s" % x509_cert_issuer.ST)
        x509_cert_issuer.C and issuer_name_list.append("C=%s" % x509_cert_issuer.C)
        # M2Crypto returns DC components in reverse order (?!?!?!?)
        DC = x509_cert_issuer.get_entries_by_nid(391)
        DC.reverse()
        for entry in DC:
            issuer_name_list.append("DC=%s" % entry.get_data())
            return X509IssuerSerialKeypairReference(','.join(issuer_name_list), x509_cert.get_serial_number())
