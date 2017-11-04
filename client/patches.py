from scapy.all import *


def TCPOptionsField_i2m_fixed(self, pkt, x):
    opt = b""
    for oname, oval in x:
        if type(oname) is str:
            if oname == "NOP":
                opt += b"\x01"
                continue
            elif oname == "EOL":
                opt += b"\x00"
                continue
            elif oname in TCPOptions[1]:
                onum = TCPOptions[1][oname]
                ofmt = TCPOptions[0][onum][1]
                if onum == 5:  # SAck
                    ofmt += "%iI" % len(oval)
                if ofmt is not None and (type(oval) is not str or "s" in ofmt):
                    if type(oval) is not tuple:
                        oval = (oval,)
                    oval = struct.pack(ofmt, *oval)
            else:
                warning("option [%s] unknown. Skipped." % oname)
                continue
        else:
            onum = oname
            # Possible problem in scapy-python3 - oval should probably be of type 'bytes' not 'str'
            # if type(oval) is not str:
            #     warning("option [%i] is not string." % onum)
            #     continue
            if type(oval) is not bytes:
                warning("option [%i] is not of type bytes." % onum)
                continue
        opt += bytes([(onum), (2 + len(oval))]) + oval
    return opt + b"\x00" * (3 - ((len(opt) + 3) % 4))
