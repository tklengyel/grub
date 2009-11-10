import re
import sys
import os
import datetime

if len (sys.argv) < 3:
    print ("Usage: %s SOURCE DESTINATION" % sys.argv[0])
    exit (0)
indir = sys.argv[1]
outdir = sys.argv[2]

basedir = os.path.join (outdir, "gcry")
try:
    os.makedirs (basedir)
except:
    print ("WARNING: %s already exists" % basedir)
cipher_dir_in = os.path.join (indir, "cipher")
cipher_dir_out = os.path.join (basedir, "cipher")
try:
    os.makedirs (cipher_dir_out)
except:
    print ("WARNING: %s already exists" % cipher_dir_out)

cipher_files = os.listdir (cipher_dir_in)
conf = open (os.path.join (outdir, "conf", "gcry.rmk"), "w")
conf.write ("# -*- makefile -*-\n\n")
chlog = ""

for cipher_file in cipher_files:
    infile = os.path.join (cipher_dir_in, cipher_file)
    outfile = os.path.join (cipher_dir_out, cipher_file)
    if cipher_file == "ChangeLog":
        continue
    chlognew = "	* %s" % cipher_file
    nch = False
    if re.match (".*\.[ch]$", cipher_file):
        isc = re.match (".*\.c$", cipher_file)
        f = open (infile, "r")
        fw = open (outfile, "w")
        fw.write ("/* This file was automatically imported with \n")
        fw.write ("   import_gcry.py. Please don't modify it */\n");
        ciphernames = []
        mdnames = []
        hold = False
        skip = False
        skip2 = False
        for line in f:
            if skip:
                if line[0] == "}":
                    skip = False
                continue
            if skip2:
                if not re.search (" *};", line) is None:
                    skip2 = False
                continue
            if hold:
                hold = False
                # We're optimising for size.
                elif not re.match ("(run_selftests|selftest|_gcry_aes_c.._..c|_gcry_[a-z0-9]*_hash_buffer)", line) is None:
                    skip = True
                    fname = re.match ("[a-zA-Z0-9_]*", line).group ()
                    chmsg = "(%s): Removed." % fname
                    if nch:
                        chlognew = "%s\n	%s" % (chlognew, chmsg)
                    else:
                        chlognew = "%s %s" % (chlognew, chmsg)
                        nch = True
                    continue
                else:
                    fw.write (holdline)
            m = re.match ("#include <.*>", line)
            if not m is None:
                chmsg = "Removed including of %s" % \
                m.group () [len ("#include <"):len (m.group ()) - 1]
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s: %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("gcry_cipher_spec_t", line)
            if isc and not m is None:
                ciphername = line [len ("gcry_cipher_spec_t"):].strip ()
                ciphername = re.match("[a-zA-Z0-9_]*",ciphername).group ()
                ciphernames.append (ciphername)
            m = re.match ("gcry_md_spec_t", line)
            if isc and not m is None:
                mdname = line [len ("gcry_md_spec_t"):].strip ()
                mdname = re.match("[a-zA-Z0-9_]*",mdname).group ()
                mdnames.append (mdname)
            m = re.match ("static const char \*selftest.*;$", line)
            if not m is None:
                fname = line[len ("static const char \*"):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed declaration." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("(static const char( |)\*|static gpg_err_code_t|void)$", line)
            if not m is None:
                hold = True
                holdline = line
                continue
            m = re.match ("cipher_extra_spec_t", line)
            if isc and not m is None:
                skip2 = True
                fname = line[len ("cipher_extra_spec_t "):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("md_extra_spec_t", line)
            if isc and not m is None:
                skip2 = True
                fname = line[len ("md_extra_spec_t "):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            fw.write (line)
        if len (ciphernames) > 0 or len (mdnames) > 0:
            modname = cipher_file [0:len(cipher_file) - 2]
            if re.match (".*-glue$", modname):
                modfiles = "gcry/cipher/%s gcry/cipher/%s" \
                    % (cipher_file, cipher_file.replace ("-glue.c", ".c"))
                modname = modname.replace ("-glue", "")
            else:
                modfiles = "gcry/cipher/%s" % cipher_file
            modname = "gcry_%s" % modname
            chmsg = "(GRUB_MOD_INIT(%s)): New function\n" % modname
            if nch:
                chlognew = "%s\n	%s" % (chlognew, chmsg)
            else:
                chlognew = "%s%s" % (chlognew, chmsg)
                nch = True
            fw.write ("\n\nGRUB_MOD_INIT(%s)\n" % modname)
            fw.write ("{\n")
            for ciphername in ciphernames:
                chmsg = "Register cipher %s" % ciphername
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_cipher_register (&%s);\n" % ciphername)
            for mdname in mdnames:
                chmsg = "Register digest %s" % mdname
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_md_register (&%s);\n" % mdname)
            fw.write ("}")
            chmsg = "(GRUB_MOD_FINI(%s)): New function\n" % modname
            chlognew = "%s\n	%s" % (chlognew, chmsg)
            fw.write ("\n\nGRUB_MOD_FINI(%s)\n" % modname)
            fw.write ("{\n")
            for ciphername in ciphernames:
                chmsg = "Unregister cipher %s" % ciphername
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_cipher_unregister (&%s);\n" % ciphername)
            for mdname in mdnames:
                chmsg = "Unregister MD %s" % mdname
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_md_unregister (&%s);\n" % mdname)
            fw.write ("}\n")
            conf.write ("pkglib_MODULES += %s.mod\n" % modname)
            conf.write ("%s_mod_SOURCES = %s\n" %\
                            (modname, modfiles))
            conf.write ("%s_mod_CFLAGS = $(COMMON_CFLAGS) -Wno-missing-field-initializers -Wno-error\n" % modname)
            conf.write ("%s_mod_LDFLAGS = $(COMMON_LDFLAGS)\n\n" % modname)
        elif isc and cipher_file != "camellia.c":
            print ("WARNING: C file isn't a module: %s" % cipher_file)
        f.close ()
        fw.close ()
        if nch:
            chlog = "%s%s\n" % (chlog, chlognew)
        continue
    if re.match ("(Manifest|Makefile\.am)$", cipher_file):
        chlog = "%s%sRemoved\n" % (chlog, chlognew)
        continue
    # Autogenerated files. Not even worth mentionning in ChangeLog
    if re.match ("Makefile\.in$", cipher_file):
        chlog = "%s%sRemoved\n" % (chlog, chlognew)
        continue
    chlog = "%s%sSkipped unknown file\n" % (chlog, chlognew)
    print ("WARNING: unknown file %s" % cipher_file)

outfile = os.path.join (cipher_dir_out, "types.h")
fw=open (outfile, "w")
fw.write ("#include <grub/types.h>\n")
fw.write ("#include <grub/cipher_wrap.h>\n")
chlog = "%s	* types.h: New file.\n" % chlog
fw.close ()

outfile = os.path.join (cipher_dir_out, "memory.h")
fw=open (outfile, "w")
fw.write ("#include <grub/cipher_wrap.h>\n")
chlog = "%s	* memory.h: New file.\n" % chlog
fw.close ()


outfile = os.path.join (cipher_dir_out, "cipher.h")
fw=open (outfile, "w")
fw.write ("#include <grub/crypto.h>\n")
fw.write ("#include <grub/cipher_wrap.h>\n")
chlog = "%s	* cipher.h: Likewise.\n" % chlog
fw.close ()

outfile = os.path.join (cipher_dir_out, "g10lib.h")
fw=open (outfile, "w")
fw.write ("#include <grub/cipher_wrap.h>\n")
chlog = "%s	* g10lib.h: Likewise.\n" % chlog
fw.close ()

infile = os.path.join (cipher_dir_in, "ChangeLog")
outfile = os.path.join (cipher_dir_out, "ChangeLog")


f=open (infile, "r")
fw=open (outfile, "w")
dt = datetime.date.today ()
fw.write ("%04d-%02d-%02d  Automatic import tool\n" % \
          (dt.year,dt.month, dt.day))
fw.write ("\n")
fw.write ("	Imported ciphers to GRUB\n")
fw.write ("\n")
fw.write (chlog)
fw.write ("\n")
for line in f:
    fw.write (line)
f.close ()
fw.close ()
