#!/usr/bin/env python
import sys,time,struct,hmac,hashlib,base64,crypt,os,re


def authenticate(secretkey):
    print >>sys.stderr,"Validation code: ",
    code_attempt=raw_input()
    tm = int(time.time() / 30)
    secretkey = base64.b32decode(secretkey)
 
    # try 30 seconds behind and ahead as well
    for ix in [-1, 0, 1]:
        # convert timestamp to raw bytes
        b = struct.pack(">q", tm + ix)
 
        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()

        # extract 4 bytes from digest based on LSB
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset+4]
 
        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF;
        code %= 1000000;
 
        if ("%06d" % code) == str(code_attempt):
            return True
 
    return False


def loginaction():
	try:
		os.system(os.environ['SSH_ORIGINAL_COMMAND'])
	except:
		os.system(os.environ['SHELL'])
	sys.exit(0)


seed=""
trustedip=""
clientip="INVALID"

if (os.environ.has_key("SSH_CLIENT")):
	r=re.match('([\d\.]+)\s+',os.environ["SSH_CLIENT"])
	if r:
		clientip=r.group(1)

dir="%s/.google_authenticator"%os.environ['HOME']
if os.path.exists(dir):
	perms=int(oct(os.stat(dir).st_mode))%10000
	if perms<=600:
		fp=open(dir,"r")
		if fp:
			for a in fp.readlines():
				a=a.rstrip()
				r=re.match('\s*seed=(.*)',a)
				if r:
					seed=r.group(1)
				r=re.match('\s*trustedip=(.*)',a)
				if r:
					trustedip=r.group(1)
				
			if clientip == trustedip:
				print >>sys.stderr,"You're from an allowed IP"
				loginaction()

			if authenticate(seed):
				loginaction()
			else:
				print >>sys.stderr,"Invalid"
	else:
		print >>sys.stderr,"Permissions are not restrictive on %s.  Should be no greater that 600"%dir


else:
	print >>sys.stderr,"Configuration file %s doesn't exist"%dir

sys.exit(1)

