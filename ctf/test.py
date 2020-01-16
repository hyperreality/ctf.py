from ctf import *
import binascii
import os
import unittest


class TestBasic(unittest.TestCase):
    def test_millerrabin(self):
        n = 1641117189524860342313448880785985676983479
        p = 16912473451

        self.assertFalse(is_prime(n))
        self.assertTrue(is_prime(p))

    def test_picoCTF_b00tl3gRSA3(self):
        os.system("rm -f siqs.dat")

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

        self.assertEqual("picoCTF{%s,%s}" % (max(primes), min(primes)), "picoCTF{73176001,67867967}")

    def test_timisoara_three_keys(self):
        # Three Chinese spies are sent on a mission to a foreign country. The evil ruler of the country has taken three primes
        p1 = 492876863
        p2 = 472882049
        p3 = 573259391

        # a secret text t < n^4, where n = p1*p2*p3 and split the text into 3 parts:
        # t1 = t mod (p1^4)
        # t2 = t^2019 mod (p2^4)
        # t3 = t^(2019^2019) mod (p3^4)
        t1 = 53994433445527579909840621536093364
        t2 = 36364162229311278067416695130494243
        t3 = 31003636792624845072184744558108878

        n1 = pow(p1, 4)
        n2 = pow(p2, 4)
        n3 = pow(p3, 4)

        c1 = t1
        c2 = pow(t2, modinv(2019, totient(p2, 4)), n2)
        c3 = pow(t3, modinv(2019**2019, totient(p3, 4)), n3)

        t = chinese_remainder([n1, n2, n3], [c1, c2, c3])

        self.assertEqual(long_to_bytes(t).decode('ascii'), "timctf{c0ngru3nc3s_4r3_s000o_c00l}")


    def test_angstrom_xor(self):
        # just to test drive the methods...
        cipher = [chr(a) for a in binascii.unhexlify("fbf9eefce1f2f5eaffc5e3f5efc5efe9fffec5fbc5e9f9e8f3eaeee7")]

        for i in range(256):
            xored = xor_strings(cipher, chr(i), extend = True)
            if printable(xored) and looks_like_english(xored, splitChar = "_"):
                break

        self.assertEqual(xored, "actf{hope_you_used_a_script}")


    @classmethod
    def tearDownClass(self):
        os.system("rm siqs.dat factor.log session.log")  # cleanup yafu crap


if __name__ == '__main__':
    unittest.main()
