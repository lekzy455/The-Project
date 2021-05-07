from binascii import unhexlify, hexlify
from pyDes import triple_des, ECB, CBC, des
import codecs


# Create your views here.
def DES_Enc(data, key):
    t = des(key, ECB, padmode=None)
    d = t.encrypt(data)
    return d


def NRKGP(key, ksn):
    print ("NRKGP")
    print ("ksn: "), hexlify(ksn)
    print ("key: "), hexlify(key)
    ksn = bytearray(ksn)
    key = bytearray(key)
    key_temp = key[:8]

    temp = bytearray()
    for i in range(8):
        temp.append(ksn[i] ^ key[8 + i])
    print ("----------------------des enc 1--------------")
    print ("temp: "), hexlify(temp)
    print ("key_temp: "), hexlify(key_temp)
    res = DES_Enc(str(temp), str(key_temp))
    key_r = bytearray(res)
    print ("key_r: "), hexlify(key_r)
    for i in range(8):
        key_r[i] ^= key[8 + i]

    key_temp[0] ^= 0xC0
    key_temp[1] ^= 0xC0
    key_temp[2] ^= 0xC0
    key_temp[3] ^= 0xC0
    key[8] ^= 0xC0
    key[9] ^= 0xC0
    key[10] ^= 0xC0
    key[11] ^= 0xC0

    print ("key: "), hexlify(key)
    print ("key_temp: "), hexlify(key_temp)
    print ("ksn: "), hexlify(ksn)
    temp = bytearray()
    for i in range(8):
        temp.append(ksn[i] ^ key[8 + i])

    print ("----------------------des enc 2--------------")
    print ("temp: "), hexlify(temp)
    print ("key_temp: "), hexlify(key_temp)
    res = DES_Enc(str(temp), str(key_temp))
    key_l = bytearray(res)
    print ("key_l: "), hexlify(key_l)
    for i in range(8):
        key[i] = key_l[i] ^ key[8 + i]
    key[8: 16] = key_r[:8]
    print ("key: "), hexlify(key)
    print ("NRKGP")
    return key


def TDES_Enc(data, key):
    t = triple_des(key, ECB, padmode=None)
    res = t.encrypt(data)
    return res


def GenerateIPEK(ksn, DK):
    temp = bytearray(ksn)[:8]
    keyTemp = bytearray(DK)[:16]
    temp[7] = 0xE0 & temp[7]
    temp2 = TDES_Enc(str(temp), str(keyTemp))
    result = temp2[:8]
    keyTemp[0] ^= 0xC0
    keyTemp[1] ^= 0xC0
    keyTemp[2] ^= 0xC0
    keyTemp[3] ^= 0xC0
    keyTemp[8] ^= 0xC0
    keyTemp[9] ^= 0xC0
    keyTemp[10] ^= 0xC0
    keyTemp[11] ^= 0xC0
    temp2 = TDES_Enc(str(temp), str(keyTemp))
    result += temp2[:8]
    return result


def GetDUKPTKey(ksn, ipek):
    print ("ksn: "), hexlify(ksn)
    print ("ipek: "), hexlify(ipek)

    key = bytearray(ipek)[:16]
    ksn = bytearray(ksn)
    cnt = bytearray()
    cnt.append(ksn[7] & 0x1F)
    cnt.append(ksn[8])
    cnt.append(ksn[9])
    temp = bytearray(8)
    temp[:6] = ksn[2:8]
    temp[5] &= 0xE0

    print ("temp: "), hexlify(temp)
    shift = 0x10
    while (shift > 0):
        #        print "11111111111"
        if ((cnt[0] & shift) > 0):
            temp[5] |= shift
            key = NRKGP(key, temp)
        shift >>= 1

    shift = 0x80
    while (shift > 0):
        #        print "2222222222222"
        if ((cnt[1] & shift) > 0):
            temp[6] |= shift
            key = NRKGP(key, temp)
        shift >>= 1

    shift = 0x80
    while (shift > 0):
        #        print "33333333333333"
        if ((cnt[2] & shift) > 0):
            print ("temp: "), hexlify(temp)
            temp[7] |= shift
            print ("temp: "), hexlify(temp)
            key = NRKGP(key, temp)
        shift >>= 1

    return key


def GetDataKeyVariant(ksn, ipek):
    key = GetDUKPTKey(ksn, ipek)
    key = bytearray(key)
    key[5] ^= 0xFF
    key[13] ^= 0xFF
    return str(key)


def GetMacKeyVariant(ksn, ipek):
    key = GetDUKPTKey(ksn, ipek)
    key = bytearray(key)
    key[6] ^= 0xFF
    key[14] ^= 0xFF
    return str(key)


def GetDataKey(ksn, ipek):
    key = GetDataKeyVariant(ksn, ipek)
    return str(TDES_Enc(key, key))


def TDES_Dec(data, key):
    t = triple_des(key, CBC, "\0\0\0\0\0\0\0\0", padmode=None)
    res = t.decrypt(data)
    return res


def GetPINKeyVariant(ksn, ipek):
    key = GetDUKPTKey(ksn, ipek)
    key = bytearray(key)
    key[7] ^= 0xFF
    key[15] ^= 0xFF
    return str(key)


def handled_unhexlify(param, datatype):
    try:
        return unhexlify(param)
    except Exception as e:
        raise Exception("error=" + e.message + ","+ " param=" + datatype)
        #raise handled_unhexlify_exception(e.message,param)


def decrypt_pinblock(ksn, data):
    BDK = handled_unhexlify("0123456789ABCDEFFEDCBA9876543210", "default")
    ksn = handled_unhexlify(ksn, "pin_ksn")
    data = handled_unhexlify(data, "pin_data")
    IPEK = GenerateIPEK(ksn, BDK)
    PIN_KEY = GetPINKeyVariant(ksn, IPEK)
    #print hexlify(PIN_KEY)
    res = TDES_Dec(data, PIN_KEY)
    return hexlify(res)


def decrypt_card_info(ksn, data):
    BDK = handled_unhexlify("0123456789ABCDEFFEDCBA9876543210",'default')
    ksn = handled_unhexlify(ksn, "card_ksn")
    data = handled_unhexlify(data, "card_data")
    IPEK = GenerateIPEK(ksn, BDK)
    DATA_KEY = GetDataKey(ksn, IPEK)
    r = hexlify(DATA_KEY)
    res = TDES_Dec(data, DATA_KEY)
    return hexlify(res)


def hextostring(hex_data):
    return codecs.decode(hex_data, 'hex')


if __name__ == "__main__":
    KSN = "ad8e1b6c5010d9c00013"
    DATA = "a8a83c06523089dd7729708d1a67defedc6ad370915120380822d240d2591a1c386fc19f4ee346ae9854f295544d7f21e63f143d0bf9fb4eeb0c3db7075a4308cd5d2ec70a27d28e"
    # DATA="153CEE49576C0B709515946D991CB48368FEA0375837ECA6"
    p = decrypt_card_info(KSN, DATA)
    Pan_tag = p.find('5a')
    name_tag = p.find('5f20')
    w = p.find('5f24')
    u = p[Pan_tag+4:Pan_tag+20]
    t = p[w+6:w+12]
    n = p[name_tag+6:name_tag+40]
    name = hextostring(n)
