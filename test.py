from ctf import *
import os
import unittest


class TestBasic(unittest.TestCase):
    def test_millerrabin(self):
        n = 1641117189524860342313448880785985676983479
        p = 16912473451

        self.assertFalse(is_prime(n))
        self.assertTrue(is_prime(p))

    def test_picoCTF_b00tl3gRSA3(self):
        os.system("rm siqs.dat")

        c = 68314351483199977654946384393853074563137175387309013664593816524333713879763562856195772252861801193963796335416196969111653281954654162684862063297222141057658940446458737761243681346192579708122053687910434192910264989089423342249800858581014301542412393895095899954834526511764319374580052227259654552160850774493105215248164590726892832669
        n = 218642365016135028522886653880280975194280379243088300409155003677301609255320230380590573935430426989266640081919755246492346653444455408925356282584404123533457702991356294798307766977645155815241667308363278127329738614315036477499695742972751303946329882654551602359158734305692150627227407886346256913532205995208720741110608078672930395369
        e = 65537

        primes = factorise(n)

        testN = 1
        for p in primes:
            testN *= p
        self.assertEqual(testN, n)

        phi = 1
        for p in primes:
            phi *= (p - 1)
        d = modinv(e, phi)

        p = pow(c, d, n)

        self.assertEqual(long_to_bytes(p).decode('ascii'),
                         "picoCTF{too_many_fact0rs_6542458}")

    def test_picoCTF_john_pollard(self):

        pubKey = rsa_cert_to_key("test_data/picoctf_cert")

        key = RSA.importKey(pubKey)
        primes = factorise(key.n)

        self.assertEqual(f"picoCTF{{{max(primes)},{min(primes)}}}", "picoCTF{73176001,67867967}")

if __name__ == '__main__':
    unittest.main()
