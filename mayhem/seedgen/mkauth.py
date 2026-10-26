import subprocess, sys, hashlib
def tlv(tag, body): 
    n=len(body)
    if n<128: l=bytes([n])
    else:
        b=n.to_bytes((n.bit_length()+7)//8,'big'); l=bytes([0x80|len(b)])+b
    return bytes([tag])+l+body
def seq(*a): return tlv(0x30,b''.join(a))
def sset(*a): return tlv(0x31,b''.join(a))
def oid(s):
    p=[int(x) for x in s.split('.')]
    out=bytes([p[0]*40+p[1]])
    for v in p[2:]:
        b=[v&0x7f]; v>>=7
        while v: b.append(0x80|(v&0x7f)); v>>=7
        out+=bytes(reversed(b))
    return tlv(6,out)
def integer(n): 
    b=n.to_bytes(max(1,(n.bit_length()+8)//8),'big'); return tlv(2,b)
def octet(b): return tlv(4,b)
def ctx(n,body,constructed=True): return tlv((0xa0 if constructed else 0x80)|n, body)
def read(d,i):
    tag=d[i]; l=d[i+1]; j=i+2
    if l&0x80:
        k=l&0x7f; l=int.from_bytes(d[j:j+k],'big'); j+=k
    return tag,j,l
cert=subprocess.check_output(['openssl','x509','-in','c.pem','-outform','DER'])
t,j,l=read(cert,0)           # Certificate
t,j2,l2=read(cert,j)         # TBSCertificate
i=j2
t,a,b=read(cert,i)
if t==0xa0: i=a+b            # skip version
t,a,b=read(cert,i); serial=cert[i:a+b]; i=a+b
t,a,b=read(cert,i); i=a+b    # signature alg
t,a,b=read(cert,i); issuer=cert[i:a+b]
sha256=seq(oid('2.16.840.1.101.3.4.2.1'),tlv(5,b''))
rsa=seq(oid('1.2.840.113549.1.1.1'),tlv(5,b''))
pe_image=seq(oid('1.3.6.1.4.1.311.2.1.15'), seq(tlv(0x03,b'\x00'), ctx(0, ctx(2, ctx(0, tlv(0x80,'<<<Obsolete>>>'.encode('utf-16-be'))))) ))
indirect=seq(pe_image, seq(sha256, octet(hashlib.sha256(b'hello lief').digest())))
content=seq(oid('1.3.6.1.4.1.311.2.1.4'), ctx(0,indirect))
authattrs=ctx(0, seq(oid('1.2.840.113549.1.9.3'), sset(oid('1.3.6.1.4.1.311.2.1.4'))) + seq(oid('1.2.840.113549.1.9.4'), sset(octet(hashlib.sha256(indirect).digest()))))
signer=seq(integer(1), seq(issuer,serial), sha256, authattrs, rsa, octet(b'\x42'*256))
signed=seq(integer(1), sset(sha256), content, ctx(0,cert), sset(signer))
out=seq(oid('1.2.840.113549.1.7.2'), ctx(0,signed))
open(sys.argv[1],'wb').write(out)
