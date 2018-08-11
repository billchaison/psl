#!/usr/bin/perl

$TABLE_BYTES = 256;
$IV_BYTES = 16;
$KEY_BYTES = 16;

@psl_source_template = get_template();

foreach $line (@psl_source_template)
{
	$aa = 0;
	$line =~ s/[\r\n]//g;
	if($line =~ /\/\/\sDYNGENERATED DATE/)
	{
		$aa = 1;
		print "// This source generated on: " . gmtime() . " GMT.\n";
	}
	if($line =~ /\/\/\sDYNGENERATED\sDYNORDERED\sA\s(.+)/)
	{
		# const uint8_t iv_bytes[TABLE_BYTES]
		# const uint8_t key_bytes[TABLE_BYTES]
		$aa = 1;
		$a = $1;
		@b = split(/,/, $a);
		$c = int(rand(@b));
		print $b[$c] . " =\n{\n";
		rand_blob();
		print "};\n\n";
		splice(@b, $c, 1);
		print $b[0] . " =\n{\n";
		rand_blob();
		print "};\n";
	}
	if($line =~ /\/\/\sDYNGENERATED\sDYNORDERED\sB\s(.+)/)
	{
		# uint8_t checkval[CHK_VAL_BYTES]
		# uint8_t dbver[BLOCK_BYTES]
		# uint8_t pslhash[HASH_BYTES_H]
		# uint8_t inthash[HASH_BYTES_H]
		# uint8_t scrhash[HASH_BYTES_H]
		# uint8_t intpath[PSL_STRING_LEN]
		# uint8_t scrpath[PSL_STRING_LEN]
		$aa = 1;
		$a = $1;
		@b = split(/,/, $a);
		print "typedef struct _db_header\n{\n";
		$c = int(rand(@b));
		print "\t" . $b[$c] . ";\n";
		splice(@b, $c, 1);
		$c = int(rand(@b));
		print "\t" . $b[$c] . ";\n";
		splice(@b, $c, 1);
		$c = int(rand(@b));
		print "\t" . $b[$c] . ";\n";
		splice(@b, $c, 1);
		$c = int(rand(@b));
		print "\t" . $b[$c] . ";\n";
		splice(@b, $c, 1);
		$c = int(rand(@b));
		print "\t" . $b[$c] . ";\n";
		splice(@b, $c, 1);
		$c = int(rand(@b));
		print "\t" . $b[$c] . ";\n";
		splice(@b, $c, 1);
		print "\t" . $b[0] . ";\n} DB_HEADER;\n";
	}
	if($line =~ /\/\/\sDYNGENERATED\sDYNORDERED\sJ/)
	{
		# initial key and IV function
		$aa = 1;
		@tb01 = ("iv_bytes", "key_bytes");
		@tb02 = ("0x80", "0x40", "0x20", "0x10");
		$a = $tb01[rand @tb01];
		$b = $tb01[rand @tb01];
		$c = $tb02[rand @tb02];
		$d = $tb02[rand @tb02];
		print "void GenInitSecrets(uint8_t *hash)\n{\n";
		print "\tuint8_t t;\n";
		print "\tint i, j, j0 = " . int(rand(256)) . ", j1 = " . int(rand(256)) . ", k = " . (int(rand(15)) + 1) . ", l = " . (int(rand(15)) + 1) . ";\n\n";
		print "\tfor(i = 0, j = j0; i < BLOCK_BYTES; i++, j += k)\n\t{\n";
		print "\t\tif(j > 255) { j -= 256; }\n";
		print "\t\tprekey[i] = key_bytes[*(hash + i)];\n";
		print "\t\tprekey[i] ^= $a" . "[j];\n";
		print "\t\tif($b" . "[i] & $c)\n";
		print "\t\t{\n\t\t\tprekey[i] = ROBL(prekey[i], $b" . "[i] & 7);\n";
		print "\t\t}\n\t\telse\n";
		print "\t\t{\n\t\t\tprekey[i] = ROBR(prekey[i], $b" . "[i] & 7);\n";
		print "\t\t}\n";
		print "\t}\n";
		print "\tfor(i = 0, j = j1; i < BLOCK_BYTES; i++, j += l)\n\t{\n";
		print "\t\tif(j > 255) { j -= 256; }\n";
		print "\t\tpreiv[i] = iv_bytes[*(hash + BLOCK_BYTES + i)];\n";
		print "\t\tpreiv[i] ^= $b" . "[j];\n";
		print "\t\tif($b" . "[i] & $d)\n";
		print "\t\t{\n\t\t\tpreiv[i] = ROBL(prekey[i], $a" . "[i] & 7);\n";
		print "\t\t}\n\t\telse\n";
		print "\t\t{\n\t\t\tpreiv[i] = ROBR(prekey[i], $a" . "[i] & 7);\n";
		print "\t\t}\n";
		print "\t}\n";
		print "\tt = preiv[0];\n";
		print "\tfor(i = 1; i < BLOCK_BYTES; i++)\n\t{\n";
		print "\t\tpreiv[i - 1] = preiv[i];\n";
		print "\t}\n";
		print "\tpreiv[15] = t;\n";
		print "}\n";
	}
	if($line =~ /\/\/\sDYNGENERATED\sDYNORDERED\sK/)
	{
		# DB key and IV function
		$aa = 1;
		@f01 = ("dbiv[i] = ROBR(dbiv[i], key_bytes[i] & 7);", "dbiv[i] = ROBL(dbiv[i], key_bytes[i] & 7);");
		@f02 = ("dbiv[i] = ROBR(dbiv[i], key_bytes[i] & 7);", "dbiv[i] = ROBL(dbiv[i], key_bytes[i] & 7);");
		@m01 = ("0x10", "0x20", "0x40", "0x80");
		$a = $f01[rand @f01];
		$b = $f02[rand @f02];
		$c = $m01[rand @m01];
		print "void GenDBSecrets(uint8_t *inthash, uint8_t *scrhash, uint8_t *pslhash, uint8_t *salt)\n{\n";
		print "\tuint8_t dbkt[KEY_BYTES], dbit[IV_BYTES];\n";
		print "\tint i;\n\n";
		print "\tfor(i = 0; i < BLOCK_BYTES; i++)\n\t{\n";
		print "\t\tdbkey[i] = key_bytes[*(inthash + i)];\n";
		print "\t\tdbkey[i] ^= key_bytes[prekey[i]];\n";
		print "\t\tdbkey[i] ^= *(pslhash + i);\n";
		print "\t\tdbkey[i] ^= *(salt + i);\n";
		print "\t\tdbiv[i] = iv_bytes[*(scrhash + i)];\n";
		print "\t\tdbiv[i] ^= iv_bytes[preiv[i]];\n";
		print "\t\tdbiv[i] ^= *(pslhash + i);\n";
		print "\t\tdbiv[i] ^= ~*(salt + i);\n\t}\n";
		print "\tKeyExpansion(round_keys, &dbkey[0]);\n";
		print "\tmemcpy(chain, &dbiv[0], IV_BYTES);\n";
		print "\tEncryptBlock(&dbkt[0], scrhash, round_keys, chain);\n";
		print "\tKeyExpansion(round_keys, &dbkt[0]);\n";
		print "\tmemcpy(chain, &dbiv[0], IV_BYTES);\n";
		print "\tEncryptBlock(&dbit[0], &dbkey[0], round_keys, chain);\n";
		print "\tmemcpy(&dbkey[0], &dbkt[0], KEY_BYTES);\n";
		print "\tmemcpy(&dbiv[0], &dbit[0], IV_BYTES);\n";
		print "\tfor(i = 0; i < IV_BYTES; i++)\n\t{\n";
		print "\t\tif(key_bytes[i] & " . $c . ")\n\t\t{\n";
		print "\t\t\t$a\n\t\t}\n\t\telse\n\t\t{\n";
		print "\t\t\t$b\n\t\t}\n\t}\n}\n";
	}
	if(!$aa)
	{
		print $line . "\n";
	}
}

sub rand_blob()
{
	undef @y;
	undef @w;
	$u = 16;
	for($z = 0; $z < $TABLE_BYTES; $z++)
	{
		push(@y, $z);
	}
	while(@y > 0)
	{
		$x = int(rand(@y));
		push(@w, $y[$x]);
		splice(@y, $x, 1);
		if(@w == 16)
		{
			print "\t";
			$u--;
			for($v = 0; $v < @w; $v++)
			{
				printf("0x%02x", $w[$v]);
				if($v == (@w - 1))
				{
					if($u)
					{
						print ",\n";
					}
					else
					{
						print "\n";
					}
				}
				else
				{
					print ", ";
				}
			}
			undef @w;
		}
	}
}

sub rand_barray()
{
	$z = int(rand(16)) + 1;
	print "[$z] = {";
	for($y = 0; $y < $z; $y++)
	{
		if(($y + 1) == $z)
		{
			printf("0x%02x};\n", int(rand(256)));
		}
		else
		{
			printf("0x%02x, ", int(rand(256)));
		}
	}
}

sub rand_ivvec()
{
	for($z = 0; $z < $IV_BYTES; $z++)
	{
		if(($z + 1) == $IV_BYTES)
		{
			printf("0x%02x};\n", int(rand(256)));
		}
		else
		{
			printf("0x%02x, ", int(rand(256)));
		}
	}
}

sub rand_keyvec()
{
	for($z = 0; $z < $KEY_BYTES; $z++)
	{
		if(($z + 1) == $KEY_BYTES)
		{
			printf("0x%02x};\n", int(rand(256)));
		}
		else
		{
			printf("0x%02x, ", int(rand(256)));
		}
	}
}

sub get_template()
{
	@template = <<'END_OF_TEMPLATE' =~ m/(^.*\n)/mg;
// START OF FILE.
// Programmatically generated source code, DO NOT MANUALLY EDIT THIS FILE.
// DYNGENERATED DATE
/*---------------------------------------------------------------------------
 Protected Script Launcher (PSL), written by Bill Chaison.

 +++ Description +++

 Offers an improvement in storing sensitive script parameters, such as
 authentication credentials, over traditional methods.  Automated tasks that
 need to run without user interaction face a challenge of where and how to
 store keys or credentials.  The usual methods of including credentials within
 scripts is to either store them in plain text, obfuscate them in some
 reversible form such as base64, XOR or rot13, use encoding/encryption methods
 where access to the decryption material may be trivial even if stored off-host
 or by protecting scripts simply with file permissions.  Approaches that use
 key retrieval methods at run-time from a key management system (KMS) may add
 complexity to the task of retrieving secrets but ultimately do not solve the
 problem, they merely relocate the problem.  Systems employing trusted host or
 application level mutual authentication and key encrypting keys (KEKs) may
 have a vulnerable implementation which can be used to circumvent security;
 given enough analysis, time and effort those weaknesses can be exploited.

 PSL does not introduce a revolutionary method to automated key retrieval but
 it does add several factors that improve on the storage and execution of
 protected scripts.  The following features and implementation criteria of PSL
 enhance the security of an automated scripting environment over less
 sophisticated techniques.

 (1)  PSL is a lightweight and self-contained Linux executable that is compiled
      from dynamically generated source code.  Each build of PSL is unique and
      is programmatically paired with database (DB) files created.  PSL
      programmatically regenerates decryption keys at run-time.
 (2)  Since PSL is self-contained you can be creative in the way it is invoked
      and accessed to augment security.  For example:
      (a) You could make the PSL executable or the created DB file ephemerally
          accessible only when it is needed.
      (b) You could build unique instances of PSL for multiple users or even
          multiple tasks on a shared automation server.
      (c) You could chain instances of PSL where the final instance that is
          called is the one that launches your script.
 (3)  PSL utilizes AES-128-CBC encryption with two key and IV phases to decrypt
      the DB file at execution time.  The DB file is integrity checked.
 (4)  PSL utilizes SHA-256 to ensure the integrity of itself, the interpreter,
      and the script at execution time.
 (5)  PSL incorporates debug detection to determine if it is being launched by
      a debugger.
 (6)  Launching a protected script with PSL involves calling PSL against an
      encrypted DB file that was created ahead of time.  The paths to the
      interpreter and script are encrypted within the DB file with the phase 1
      key and IV, which hides the actual script path from view.
 (7)  PSL passes secrets to the interpreter and script you specify as
      environment variables instead of command line arguments.  The environment
      variables are encrypted within the DB file using the phase 2 key and IV.
 (8)  Some best practices in configuring your automation host:
      (a) Remove or control access to debugging and diagnostic tools such as
          gdb, strace, ltrace, ptrace, objdump, etc.
      (b) Control and audit root user access, since root has the ability to
          view the /proc filesystem for all processes and can override file
          permissions.
      (c) Do not store the psl.c file or psl.pl script on the automation host
          where the PSL executable resides.  Do not store the psl.c file or
          psl.pl script on the host where your DB files reside.  Do not destroy
          the psl.pl and psl.c files in the event that you need to recompile.
      (d) Compile PSL using the gcc "-s" option to strip out the symbol table.
          The symbol table makes it easier to reverse engineer the PSL binary.
          Optionally take advantage of ASLR by using -fPIE -pie.
      (e) Limit read/write/execute permissions on each instance of PSL, the
          protected script and its associated DB file to the user account it is
          being launched under.
      (f) Store the DB file on a host or on tethered media apart from the
          automation host that is running the PSL executable.  Since the
          reconstitution of secrets stored in the DB file requires the specific
          copy of the PSL executable that created it separating the two ensures
          that secrets are not recoverable if only one component is obtained.
      (g) There are 16 environment variables that can be passed to your script.
          These do not need to be used only for usernames and passwords.  You
          could hide other information, such as target device IP addresses,
          hashes of child scripts and support files for additional integrity
          checking, to mention just a few.

 +++ Installation +++

 (1) obtain a copy of psl.pl from https://github.com/billchaison/psl
 (2) chmod +x psl.pl
 (3) ./psl.pl > psl.c
 (4) gcc -s -o psl psl.c [or] gcc -s -fPIE -pie -o psl psl.c
 (5) move psl.c and psl.pl off of the host that runs the psl executable
 (6) execute ./psl without parameters for basic help
 (7) follow system hardening best practices from bullet (8) above.

 +++ Application Overview +++

 Once you have compiled PSL execute it from the command line without
 arguments to get help.  The goal of this program is to hide the path of an
 interpreter and protected script as well as encrypting secrets within an
 AES encrypted DB file, along with the SHA-256 hash of the launcher, the
 interpreter and the script to ensure that they have not been altered.  This
 allows for secure script execution and role separation on a shared automation
 server.  When PSL is executed against a DB file the PSL image is integrity
 checked, as are the interpreter, script and DB file itself.  If all of these
 checks are successful then the environment variables are passed to your script
 where they can be used to perform a privileged operation.  An example would be
 an Expect script in a cron job that logs into a router via SSH to execute a
 command.  Once you have completed the development and testing of your script
 you call "psl init" against the interpreter and script, and create a DB file
 as output.  E.g. "psl init /bin/bash /home/user/s1.sh /home/user/s1.db".  The
 interpreter, script and PSL binary will be hashed using SHA-256.  The hashes
 are stored in the encrypted DB file using the phase 1 key and IV that are
 derived at run-time by dynamically generated functions and substitution tables
 embedded into the copy of the PSL executable that you compiled.  The SHA-256
 hash of the PSL executable, interpreter and script are checked when invoking
 "psl exec" to ensure that they haven't been tampered with.  If the hashes
 do not match then "psl exec" will exit with an error.  If the hashes are valid
 then PSL generates a phase 2 key and IV from random data found in the DB file.
 This key is used to decrypt the environment variable values that are passed to
 your script via the interpreter you specified.  If you modify your script or
 the interpreter is updated then you must recreate your DB file as done
 previously using the "psl init" option.  Executing "psl init" will also prompt
 you to define 16 environment variables that can be passed to your script.  The
 environment variable names are predefined but their values can be whatever you
 specify.  If the script you specify when executing "psl init" calls other
 scripts you must ensure the integrity of those scripts; only the parent script
 and its interpreter are integrity checked by PSL.  Since the PSL binary is
 compiled from source that uses dynamic data structures and functions every DB
 file that is created is paired with a specific copy of PSL.  A different PSL
 executable cannot be used to read your DB file.

 +++ Application Usage +++

 psl init <interpreter> <script> <db file>
 psl exec <db file>

 (example: create a DB file)

 psl init /usr/bin/expect /home/user/getarptable /home/user/getarptable.db

   [ * the SHA-256 hash is taken of PSL, the interpreter and the script  ]
   [ * you will then be prompted to enter 16 environment variable values ]
   [ * you can enter a blank line for variables that will be unused      ]
   [ * the environment variable names are predefined PSLENVVAR01 .. 16   ]
   [ * the DB file is encrypted in two parts:                            ]
   [   (1) the header is encrypted using keys derived from randomized    ]
   [       functions and data structures along with the PSL hash         ]
   [   (2) the environment variables are encrypted using keys derived    ]
   [       from randomized functions & data structures, random DB salt,  ]
   [       the interpreter hash, script hash and PSL hash                ]

 (example: execute script using DB file)

 psl exec /home/user/getarptable.db

   [ * the DB file is checked for pairing with the copy of the binary    ]
   [ * the interpreter and script name are decrypted from the DB file    ]
   [ * the SHA-256 hash is taken of PSL, the interpreter and the script  ]
   [ * hashes in the DB file are decrypted and compared for integrity    ]
   [ * environment variables are decrypted with a secondary derived key  ]
   [ * the interpreter is launched with the script as its argument       ]
   [ * only non-empty environment variables are passed to the script     ]
   [ * the interpreter's status code is returned from PSL                ]
 
---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------
 This program is released under the "BSD Modified" license.

 Copyright (c) 2015, 2018 - Bill Chaison, all rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
 3. Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------
Cryptographic function notes:

Derived from and validated against:
   NIST FIPS PUB 197
   NIST SP 800-38A
   NIST FIPS PUB 180-4

Computing a SHA-256 hash:
 - Simply call the HashData function on some data.

Encrypting some plaintext (PT) to get a block of cipher text (CT):
 - Padding is not performed so PT must be BLOCK_BYTES in size and PT total
   must = 0 mod BLOCK_BYTES.
 - Acquire the key and IV.
 - Call the KeyExpansion function to create the key schedule (KS).
 - Call the EncryptBlock function on each block of PT to emit a block of CT.
   EncryptBlock consumes BLOCK_BYTES of PT, KS and IV.  IV is rewritten
   with CT in order to satisfy CBC.

Decrypting some cipher text (CT) to get a block of plaintext (PT):
 - CT must be BLOCK_BYTES in size.
 - Acquire the key and IV.
 - Call the KeyExpansion function to create the key schedule (KS).
 - Call the DecryptBlock function on each block of CT to emit a block of PT.
   DecryptBlock consumes BLOCK_BYTES of CT, KS and IV.  IV is rewritten
   with CT in order to satisfy CBC.

AES-128-CBC functions are application-specific to PSL. If you port this code
for any other application you will need to handle padding.  Byte-oriented
operations have been chosen to minimize the impact of endianness from the
underlying hardware; readability and portability chosen over optimization.
---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------
Data structures and operation:

(generated at runtime)
A, the phase 1 prekey derived from PSL hash, dynamic source functions and tables
B, the phase 1 preiv derived from PSL hash, dynamic source functions and tables
C, SHA-256 hash of interpreter
D, SHA-256 hash of script
E, SHA-256 hash of PSL binary
F, the phase 2 dbkey generated by dynamic source functions and tables using 'A', 'C', 'E' and random salt
G, the phase 2 dbiv generated by dynamic source functions and tables using 'B', 'D', 'E' and random salt

(the DB in bytes)
.......	randomly ordered header, 384 bytes total, encrypted using 'A' and 'B'
[16]	CHK_VALUE of length CHK_VAL_BYTES
[16]	4 dbver_bytes followed by 12 random characters (salt)
[32]	pslhash containing the SHA-256 of the PSL binary
[32]	inthash containing the SHA-256 of the interpreter
[32]	scrhash containing the SHA-256 of the script
[128]	interpreter path ASCIIZ, max char PSL_STRING_LEN
[128]	script path ASCIIZ, max char PSL_STRING_LEN
.......	environment variable array, 1536 bytes total, encrypted using 'F' and 'G'
[12]	"PSLENVVAR01"
[12]	"PSLENVVAR02"
[12]	"PSLENVVAR03"
[12]	"PSLENVVAR04"
[12]	"PSLENVVAR05"
[12]	"PSLENVVAR06"
[12]	"PSLENVVAR07"
[12]	"PSLENVVAR08"
[12]	"PSLENVVAR09"
[12]	"PSLENVVAR10"
[12]	"PSLENVVAR11"
[12]	"PSLENVVAR12"
[12]	"PSLENVVAR13"
[12]	"PSLENVVAR14"
[12]	"PSLENVVAR15"
[12]	"PSLENVVAR16"
[84]	PSLENVVAR01 value of EVAR_VAL_LEN
[84]	PSLENVVAR02 value of EVAR_VAL_LEN
[84]	PSLENVVAR03 value of EVAR_VAL_LEN
[84]	PSLENVVAR04 value of EVAR_VAL_LEN
[84]	PSLENVVAR05 value of EVAR_VAL_LEN
[84]	PSLENVVAR06 value of EVAR_VAL_LEN
[84]	PSLENVVAR07 value of EVAR_VAL_LEN
[84]	PSLENVVAR08 value of EVAR_VAL_LEN
[84]	PSLENVVAR09 value of EVAR_VAL_LEN
[84]	PSLENVVAR10 value of EVAR_VAL_LEN
[84]	PSLENVVAR11 value of EVAR_VAL_LEN
[84]	PSLENVVAR12 value of EVAR_VAL_LEN
[84]	PSLENVVAR13 value of EVAR_VAL_LEN
[84]	PSLENVVAR14 value of EVAR_VAL_LEN
[84]	PSLENVVAR15 value of EVAR_VAL_LEN
[84]	PSLENVVAR16 value of EVAR_VAL_LEN
.......	fixed DB file size total 1920 bytes
---------------------------------------------------------------------------*/

#pragma pack(1)

#include <stdint.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#define PRODUCT			"Protected Script Launcher (PSL)"
#define APP_VERSION		"1.1.0"
#define CRYPTOFX		"AES-128-CBC and SHA-256."
#define CHK_VALUE		"BCPSL-0123456789" // must be CHK_VAL_BYTES bytes long
#define BLOCK_BYTES		16
#define KEY_BYTES		BLOCK_BYTES
#define IV_BYTES		BLOCK_BYTES
#define TABLE_BYTES		256
#define NUM_ROUNDS		10
#define RK_BYTES		((NUM_ROUNDS * KEY_BYTES) + KEY_BYTES)
#define WORD_BYTES		4
#define WORD_BITS_H		32
#define WORD_BYTES_H		4
#define HASH_BYTES_H		32
#define BLOCK_BYTES_H		64
#define LEN_BYTES_H		8
#define BYTE_BITS		8
#define ENV_VAR_STR		"PSLENVVAR" // maximum 9 characters (EVAR_NAME_LEN - 3)
				            // PSLENVVAR01 .. PSLENVVAR16
#define DB_SALT_BYTES		12
#define CHK_VAL_BYTES		BLOCK_BYTES
#define PSL_STRING_LEN		128
#define PSL_EVARS		16
#define EVAR_VAL_LEN		84
#define EVAR_NAME_LEN		12
#define BAD_SHELL_CHARS		"'\"<>|;(){}[]&?=$\\*!"

#define ROR(a, b) (((a) >> (b)) | ((a) << (WORD_BITS_H - (b))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define SIG1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define sig0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define sig1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

typedef struct
{
	uint8_t data[BLOCK_BYTES_H];
	uint32_t datalen;
	uint64_t bitlen;
	uint32_t state[8];
} SHA256; // SHA context

typedef struct
{
	uint8_t evname[EVAR_NAME_LEN * PSL_EVARS];
	uint8_t evvalue[EVAR_VAL_LEN * PSL_EVARS];
} EVAR_TBL; // Environment variable table

// dynamically ordered and filled IV and key arrays.
// DYNGENERATED DYNORDERED A const uint8_t iv_bytes[TABLE_BYTES],const uint8_t key_bytes[TABLE_BYTES]

// dynamically ordered, PSL DB header.
// DYNGENERATED DYNORDERED B uint8_t checkval[CHK_VAL_BYTES],uint8_t dbver[BLOCK_BYTES],uint8_t pslhash[HASH_BYTES_H],uint8_t inthash[HASH_BYTES_H],uint8_t scrhash[HASH_BYTES_H],uint8_t intpath[PSL_STRING_LEN],uint8_t scrpath[PSL_STRING_LEN]

// Rijndael substitution box.
const uint8_t rsbox[TABLE_BYTES] =
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Rijndael inverse substitution box.
const uint8_t irsbox[TABLE_BYTES] =
{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rijndael round constants, max rcon[10] used for AES-128.
const uint8_t rcon[TABLE_BYTES] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

// SHA-256 constants.
uint32_t hcon[BLOCK_BYTES_H] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint8_t round_keys[RK_BYTES];
uint8_t dbver_bytes[WORD_BYTES] = {1, 1, 0, 0};
uint8_t prekey[KEY_BYTES];
uint8_t preiv[IV_BYTES];
uint8_t chain[IV_BYTES];
DB_HEADER dbh;
EVAR_TBL evt;
uint8_t *pdbhe, *pdbhd, *pdbre, *pdbrd;
uint8_t dbkey[KEY_BYTES];
uint8_t dbiv[IV_BYTES];

void Usage();
void PrintHelp();
void PrintLicense();
void StoreLength(uint64_t len, uint8_t *vec);
void WordToVec(uint32_t w, uint8_t *vec);
void VecToWord(uint32_t *w, uint8_t *vec);
void Initialize(SHA256 *sha);
void Update(SHA256 *sha, uint8_t *data, uint32_t len);
void Transform(SHA256 *sha, uint8_t *data);
void Finish(SHA256 *sha, uint8_t *hash);
void HashData(uint8_t *hash, uint8_t *in, uint32_t inlen);
int GetFileHash(char *fn, uint8_t *hash);
uint8_t ROBL(uint8_t b, uint8_t r);
uint8_t ROBR(uint8_t b, uint8_t r);
void GenInitSecrets(uint8_t *hash);
int GetProcHash(uint8_t *hash);
void EncryptBlock(uint8_t *ctblk, uint8_t *ptblk, uint8_t *rkeys, uint8_t *chain);
void DecryptBlock(uint8_t *ctblk, uint8_t *ptblk, uint8_t *rkeys, uint8_t *chain);
void KeyExpansion(uint8_t *rkeys, const uint8_t *ukey);
void Rotate(uint8_t *vec);
void SubstBytes(uint8_t *vec);
void InvSubstBytes(uint8_t *vec);
void ShiftRows(uint8_t *vec);
void InvShiftRows(uint8_t *vec);
void MixColumns(uint8_t *vec);
void InvMixColumns(uint8_t *vec);
void AddRoundKey(uint8_t *vec, uint8_t *rkeys, int rnum);
uint8_t GM2(uint8_t b);
uint8_t GM3(uint8_t b);
uint8_t GM9(uint8_t b);
uint8_t GM11(uint8_t b);
uint8_t GM13(uint8_t b);
uint8_t GM14(uint8_t b);
void GenDBSecrets(uint8_t *inthash, uint8_t *scrhash, uint8_t *pslhash, uint8_t *salt);
int EnableEcho(struct termios *oflags);
int DisableEcho(struct termios *oflags);
void FlushStdIn();

int main(int argc, char **argv)
{
	FILE *fp;
	char str[2048], *pc, *irp, *srp, evnt[EVAR_NAME_LEN + 1], linein[EVAR_VAL_LEN];
	char cmd[PSL_STRING_LEN * 3];
	int tp = 1, i, j, fd;
	long fsize;
	size_t br;
	struct termios oflags;
	uint8_t *pt;

	// Disallow launching under a debugger.
	if((fp = fopen("/proc/self/status", "r")) == NULL)
	{
		fprintf(stderr, "Failed to read process status.\n");

		return -1;
	}
	while(!feof(fp))
	{
		if(fgets(str, 2048, fp) != NULL)
		{
			if(pc = strstr(str, "TracerPid:"))
			{
				while(*pc)
				{
					if(*pc >= '0' && *pc <= '9')
					{
						tp = atoi(pc);
						break;
					}
					pc++;
				}
				break;
			}
		}
	}
	fclose(fp);
	if(tp != 0)
	{
		fprintf(stderr, "Launching from a debugger is not permitted.\n");

		return -1;
	}
	// check program parameters.
	if(argc != 3 && argc != 5)
	{
		Usage();
	}
	if(argc == 5)
	{
		// perform init routines
		if(strcmp(argv[1], "init")) { Usage (); }
		// validate interpreter, script and DB path characters
		for(i = 0; i < strlen(argv[2]); i++)
		{
			for(j = 0; j < strlen(BAD_SHELL_CHARS); j++)
			{
				if(*(argv[2] + i) == BAD_SHELL_CHARS[j])
				{
					fprintf(stderr, "The interpreter path cannot contain special characters.\n");

					return -1;
				}
			}
		}
		for(i = 0; i < strlen(argv[3]); i++)
		{
			for(j = 0; j < strlen(BAD_SHELL_CHARS); j++)
			{
				if(*(argv[3] + i) == BAD_SHELL_CHARS[j])
				{
					fprintf(stderr, "The script path cannot contain special characters.\n");

					return -1;
				}
			}
		}
		for(i = 0; i < strlen(argv[4]); i++)
		{
			for(j = 0; j < strlen(BAD_SHELL_CHARS); j++)
			{
				if(*(argv[4] + i) == BAD_SHELL_CHARS[j])
				{
					fprintf(stderr, "The DB path cannot contain special characters.\n");

					return -1;
				}
			}
		}
		// get the full path of the interpreter and script
		if((irp = realpath(argv[2], NULL)) == NULL)
		{
			fprintf(stderr, "Failed to determine the real path of the interpreter.\n");

			return -1;
		}
		if(strlen(irp) > (PSL_STRING_LEN - 1))
		{
			fprintf(stderr, "Interpreter path too long.\n");
			free(irp);

			return -1;
		}
		if((srp = realpath(argv[3], NULL)) == NULL)
		{
			fprintf(stderr, "Failed to determine the real path of the script.\n");
			free(irp);

			return -1;
		}
		if(strlen(srp) > (PSL_STRING_LEN - 1))
		{
			fprintf(stderr, "Script path too long.\n");
			free(irp);
			free(srp);

			return -1;
		}
		memset(dbh.intpath, 0, PSL_STRING_LEN);
		memset(dbh.scrpath, 0, PSL_STRING_LEN);
		strcpy(dbh.intpath, irp);
		strcpy(dbh.scrpath, srp);
		free(irp);
		free(srp);
		// read and hash the interpreter program
		if(GetFileHash(dbh.intpath, &dbh.inthash[0]) != 0)
		{
			fprintf(stderr, "Failed to get the interpreter hash.\n");

			return -1;
		}
		// read and hash the script
		if(GetFileHash(dbh.scrpath, &dbh.scrhash[0]) != 0)
		{
			fprintf(stderr, "Failed to get the script hash.\n");

			return -1;
		}
		// read and hash the PSL image
		if(GetProcHash(&dbh.pslhash[0]) == -1)
		{
			fprintf(stderr, "Failed to get the PSL image hash.\n");

			return -1;
		}
		// fill remaining parts of the DB header
		memcpy(dbh.checkval, CHK_VALUE, CHK_VAL_BYTES);
		memcpy(dbh.dbver, dbver_bytes, WORD_BYTES);
		if((fp = fopen("/dev/urandom", "rb")) != NULL)
		{
			fread(&dbh.dbver[BLOCK_BYTES - DB_SALT_BYTES], 1, DB_SALT_BYTES, fp);
			fclose(fp);
		}
		else
		{
			fprintf(stderr, "Failed to get random data.\n");

			return -1;
		}
		// generate the initial DB encryption key and IV
		GenInitSecrets(&dbh.pslhash[0]);
		// encrypt DB header
		if((pdbhe = (uint8_t *)malloc(sizeof(DB_HEADER))) == NULL)
		{
			fprintf(stderr, "Failed to allocate buffer for DB header encryption.\n");

			return -1;
		}
		KeyExpansion(round_keys, prekey);
		memcpy(chain, preiv, IV_BYTES);
		for(i = 0; i < sizeof(DB_HEADER); i += BLOCK_BYTES)
		{
			EncryptBlock(pdbhe + i, ((uint8_t *)&dbh) + i, round_keys, chain);
		}
		// derive DB key and IV.
		GenDBSecrets(&dbh.inthash[0], &dbh.scrhash[0], &dbh.pslhash[0], &dbh.dbver[0]);
		// prompt for user input, 16 environment variables
		memset(&evt, 0, sizeof(EVAR_TBL));
		for(i = 0; i < PSL_EVARS; i++)
		{
			sprintf(evnt, "%s%02d", ENV_VAR_STR, i + 1);
			memcpy(&evt.evname[i * EVAR_NAME_LEN], &evnt, EVAR_NAME_LEN);
		}
		if(tcgetattr(fileno(stdin), &oflags) != 0)
		{
			fprintf(stderr, "Failed to save terminal attributes.\n");
			free(pdbhe);

			return -1;
		}
		fprintf(stdout, "Do you wish to suppress terminal echo while entering secrets? (y/n) ");
		fgets(linein, EVAR_VAL_LEN, stdin);
		FlushStdIn();
		if(linein[0] == 'y' || linein[0] == 'Y')
		{
			if(DisableEcho(&oflags))
			{
				fprintf(stdout, "WARNING: Failed to suppress echo.  Input will be displayed.\n\n");
			}
			else
			{
				fprintf(stdout, "Input will not be displayed.\n\n");
			}
		}
		else
		{
			fprintf(stdout, "WARNING: Input will be displayed.\n\n");
		}
		for(i = 0; i < PSL_EVARS; i++)
		{
			memcpy(&evnt, &evt.evname[i * EVAR_NAME_LEN], EVAR_NAME_LEN);
			evnt[EVAR_NAME_LEN] = 0;
			fprintf(stdout, "Enter the value for %s, maximum %d characters.\nEnter a blank line to skip assigning a value.\n", evnt, EVAR_VAL_LEN - 1);
			memset(&linein[0], 0, EVAR_VAL_LEN);
			fgets(linein, EVAR_VAL_LEN, stdin);
			FlushStdIn();
			if(linein[0] >= ' ')
			{
				memcpy(&evt.evvalue[i * EVAR_VAL_LEN], &linein, EVAR_VAL_LEN);
				for(j = 0; j < EVAR_VAL_LEN; j++)
				{
					if(evt.evvalue[(i * EVAR_VAL_LEN) + j] < ' '){ evt.evvalue[(i * EVAR_VAL_LEN) + j] = 0; } // delete '\n'
				}
			}
		}
		if(EnableEcho(&oflags))
		{
			fprintf(stdout, "\nFailed to restore terminal echo.\n");
		}
		// encrypt DB records
		if((pdbre = (uint8_t *)malloc(sizeof(EVAR_TBL))) == NULL)
		{
			fprintf(stderr, "Failed to allocate buffer for DB record encryption.\n");
			free(pdbhe);

			return -1;
		}
		KeyExpansion(round_keys, dbkey);
		memcpy(chain, dbiv, IV_BYTES);
		for(i = 0; i < sizeof(EVAR_TBL); i += BLOCK_BYTES)
		{
			EncryptBlock(pdbre + i, ((uint8_t *)&evt) + i, round_keys, chain);
		}
		// create the DB file
		if((fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, S_IFREG | S_IRUSR | S_IWUSR)) == -1)
		{
			fprintf(stderr, "Failed to create the DB file.\n");
			free(pdbhe);
			free(pdbre);

			return -1;
		}
		if(write(fd, pdbhe, sizeof(DB_HEADER)) != sizeof(DB_HEADER))
		{
			fprintf(stderr, "Failed to save header to the DB file.\n");
			free(pdbhe);
			free(pdbre);
			close(fd);
			remove(argv[4]);

			return -1;
		}
		if(write(fd, pdbre, sizeof(EVAR_TBL)) != sizeof(EVAR_TBL))
		{
			fprintf(stderr, "Failed to save records to the DB file.\n");
			free(pdbhe);
			free(pdbre);
			close(fd);
			remove(argv[4]);

			return -1;
		}
		free(pdbhe);
		free(pdbre);
		close(fd);
	}
	if(argc == 3)
	{
		// perform exec routines
		if(strcmp(argv[1], "exec")) { Usage (); }
		// open the DB file and validate the header
		if((fp = fopen(argv[2], "rb")) == NULL)
		{
			fprintf(stderr, "Failed to open the DB file.\n");

			return -1;
		}
		fseek(fp, 0, SEEK_END);
		fsize = ftell(fp);
		if(fsize != sizeof(DB_HEADER) + sizeof(EVAR_TBL))
		{
			fprintf(stderr, "DB file size integrity check failed.\n");
			fclose(fp);

			return -1;
		}
		rewind(fp);
		// allocate DB read and decryption buffers
		if((pt = (uint8_t *)malloc(sizeof(DB_HEADER) + sizeof(EVAR_TBL))) == NULL)
		{
			fprintf(stderr, "Failed to allocate DB file read buffer.\n");
			fclose(fp);

			return -1;
		}
		if((pdbhd = (uint8_t *)malloc(sizeof(DB_HEADER))) == NULL)
		{
			fprintf(stderr, "Failed to allocate buffer for DB header decryption.\n");
			fclose(fp);
			free(pt);

			return -1;
		}
		if((pdbrd = (uint8_t *)malloc(sizeof(EVAR_TBL))) == NULL)
		{
			fprintf(stderr, "Failed to allocate buffer for DB record decryption.\n");
			fclose(fp);
			free(pt);
			free(pdbhd);

			return -1;
		}
		if((br = fread(pt, 1, fsize, fp)) != fsize)
		{
			fprintf(stderr, "Failed to read DB file contents.\n");
			fclose(fp);
			free(pt);
			free(pdbhd);
			free(pdbrd);

			return -1;
		}
		fclose(fp);
		// read and hash the PSL image
		if(GetProcHash(&dbh.pslhash[0]) == -1)
		{
			fprintf(stderr, "Failed to get the PSL image hash.\n");
			free(pt);
			free(pdbhd);
			free(pdbrd);

			return -1;
		}
		// generate the initial DB decryption key and IV
		GenInitSecrets(&dbh.pslhash[0]);
		// decrypt DB header
		KeyExpansion(round_keys, prekey);
		memcpy(chain, preiv, IV_BYTES);
		for(i = 0; i < sizeof(DB_HEADER); i += BLOCK_BYTES)
		{
			DecryptBlock(pdbhd + i, pt + i, round_keys, chain);
		}
		// integrity check header
		for(i = 0; i < CHK_VAL_BYTES; i++)
		{
			if(((DB_HEADER *)pdbhd)->checkval[i] != CHK_VALUE[i])
			{
				fprintf(stderr, "DB file signature or PSL image integrity check failed.\n");
				free(pt);
				free(pdbhd);
				free(pdbrd);

				return -1;
			}
		}
		// integrity check header
		if(*(uint32_t *)(&((DB_HEADER *)pdbhd)->dbver[0]) != *(uint32_t *)&dbver_bytes[0])
		{
			fprintf(stderr, "DB file version check failed.\n");
			free(pt);
			free(pdbhd);
			free(pdbrd);

			return -1;
		}
		// validate the PSL image hash
		for(i = 0; i < HASH_BYTES_H; i++)
		{
			if(((DB_HEADER *)pdbhd)->pslhash[i] != dbh.pslhash[i])
			{
				fprintf(stderr, "PSL image integrity check failed.\n");
				free(pt);
				free(pdbhd);
				free(pdbrd);

				return -1;
			}
		}
		// read and hash the interpreter program
		if(GetFileHash(&((DB_HEADER *)pdbhd)->intpath[0], &dbh.inthash[0]) != 0)
		{
			fprintf(stderr, "Failed to get the interpreter hash.\n");
			free(pt);
			free(pdbhd);
			free(pdbrd);

			return -1;
		}
		for(i = 0; i < HASH_BYTES_H; i++)
		{
			if(((DB_HEADER *)pdbhd)->inthash[i] != dbh.inthash[i])
			{
				fprintf(stderr, "Interpreter integrity check failed.\n");
				free(pt);
				free(pdbhd);
				free(pdbrd);

				return -1;
			}
		}
		// read and hash the script
		if(GetFileHash(&((DB_HEADER *)pdbhd)->scrpath[0], &dbh.scrhash[0]) != 0)
		{
			fprintf(stderr, "Failed to get the script hash.\n");
			free(pt);
			free(pdbhd);
			free(pdbrd);

			return -1;
		}
		for(i = 0; i < HASH_BYTES_H; i++)
		{
			if(((DB_HEADER *)pdbhd)->scrhash[i] != dbh.scrhash[i])
			{
				fprintf(stderr, "Script integrity check failed.\n");
				free(pt);
				free(pdbhd);
				free(pdbrd);

				return -1;
			}
		}
		// derive DB key and IV.
		GenDBSecrets(&dbh.inthash[0], &dbh.scrhash[0], &dbh.pslhash[0], &((DB_HEADER *)pdbhd)->dbver[0]);
		// decrypt DB records
		KeyExpansion(round_keys, dbkey);
		memcpy(chain, dbiv, IV_BYTES);
		for(i = 0; i < sizeof(EVAR_TBL); i += BLOCK_BYTES)
		{
			DecryptBlock(pdbrd + i, pt + sizeof(DB_HEADER) + i, round_keys, chain);
		}
		// integrity check DB records
		for(i = 0; i < PSL_EVARS; i++)
		{
			if(strncmp(pdbrd + (i * EVAR_NAME_LEN), ENV_VAR_STR, (EVAR_NAME_LEN - 3)))
			{
				fprintf(stderr, "DB record integrity check failed.\n");
				free(pt);
				free(pdbhd);
				free(pdbrd);

				return -1;
			}
		}
		// set environment variables that are defined
		for(i = 0; i < PSL_EVARS; i++)
		{
			if(strlen(&((EVAR_TBL *)pdbrd)->evvalue[i * EVAR_VAL_LEN]))
			{
				if(setenv(pdbrd + (i * EVAR_NAME_LEN), &((EVAR_TBL *)pdbrd)->evvalue[i * EVAR_VAL_LEN], 1))
				{
					fprintf(stderr, "Failed to set environment variable.\n");
					free(pt);
					free(pdbhd);
					free(pdbrd);

					return -1;
				}
			}
		}
		// execute the interpreter and script, even if no environment variables passed
		snprintf(cmd, sizeof(cmd), "'%s' '%s'", &((DB_HEADER *)pdbhd)->intpath[0], &((DB_HEADER *)pdbhd)->scrpath[0]);
		j = system(cmd);
		free(pt);
		free(pdbhd);
		free(pdbrd);

		// return the status from the interpreter
		return j;
	}

	return 0;
}

void Usage()
{
	PrintHelp();
	PrintLicense();

	exit(-1);
}

void PrintHelp()
{
	fprintf(stderr, "How to use %s version %s\n", PRODUCT, APP_VERSION);
	fprintf(stderr, "Incorporates the following cryptographic functions:\n %s\n\n", CRYPTOFX);
	fprintf(stderr, "[ Initialize a new DB file ]\n");
	fprintf(stderr, " psl init <interpreter> <script> <db file>\n\n");
	fprintf(stderr, " Creates a new database file programmatically paired with this instance\n");
	fprintf(stderr, " of the executable.  If the database file exists it will be overwritten.\n");
	fprintf(stderr, " The SHA-256 hashes of the PSL executable, <interpreter> and <script> are\n");
	fprintf(stderr, " encrypted and stored in the DB.  These stored hash values are compared\n");
	fprintf(stderr, " at run-time when using the \"exec\" mode.  If the hashes do not match\n");
	fprintf(stderr, " then PSL returns an error.  When creating a DB file you will be prompted\n");
	fprintf(stderr, " to enter 16 environment variables that can be passed to your script in\n");
	fprintf(stderr, " \"exec\" mode.  The variable names are predefined as PSLENVVAR01 through\n");
	fprintf(stderr, " PSLENVVAR16 but the values can be any string up to %d characters long.\n\n", EVAR_VAL_LEN - 1);
	fprintf(stderr, "[ Launch a script ]\n");
	fprintf(stderr, " psl exec <db file>\n\n");
	fprintf(stderr, " Launches a script passed to an interpreter from a previously created\n");
	fprintf(stderr, " <db file> that is paired with this instance of PSL.  The PSL binary,\n");
	fprintf(stderr, " interpreter, script and DB file are integrity checked prior to execution.\n");
	fprintf(stderr, " The environment variables are decrypted using a key derived at run-time.\n");
	fprintf(stderr, " All non-empty values are passed to the script.\n\n");
}

void PrintLicense()
{
	char *license = "\
 Released under the terms of the BSD 3-Clause \"BSD Modified\" license.\n\
\n\
 Copyright (c) 2015, 2018 - Bill Chaison\n\
 All rights reserved.\n\
\n\
 Redistribution and use in source and binary forms, with or without \n\
 modification, are permitted provided that the following conditions \n\
 are met:\n\
\n\
 1. Redistributions of source code must retain the above copyright notice,\n\
    this list of conditions and the following disclaimer.\n\
 2. Redistributions in binary form must reproduce the above copyright notice,\n\
    this list of conditions and the following disclaimer in the documentation\n\
    and/or other materials provided with the distribution.\n\
 3. Neither the name of the copyright holder nor the names of its\n\
    contributors may be used to endorse or promote products derived from this\n\
    software without specific prior written permission.\n\
\n\
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n\
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n\
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n\
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n\
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n\
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n\
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n\
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n\
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n\
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n\
 POSSIBILITY OF SUCH DAMAGE.";

	fprintf(stdout, "[ License ]\n%s\n", license);
	fprintf(stdout, "\n");
}

void StoreLength(uint64_t len, uint8_t *vec)
{
	// Fills vec with the data length as a 64-bit int.
	uint64_t i = 72057594037927936;

	while(i > 255)
	{
		if(len >= i)
		{
			*vec = len / i;
			len -= *vec * i;
		}
		else
		{
			*vec = 0;
		}
		i /= 256;
		vec++;
	}
	*vec = len;
}

void WordToVec(uint32_t w, uint8_t *vec)
{
	// Convert a 32-bit word to a 4-byte vector, ignore endianness.
	uint32_t i = 16777216;

	while(i > 255)
	{
		if(w >= i)
		{
			*vec = w / i;
			w -= *vec * i;
		}
		else
		{
			*vec = 0;
		}
		i /= 256;
		vec++;
	}
	*vec = w;
}

void VecToWord(uint32_t *w, uint8_t *vec)
{
	// Convert a 4-byte vector to a 32-bit word, ignore endianness.
	uint32_t i = 16777216;

	*w = 0;
	while(i > 255)
	{
		*w += (*vec * i);
		i /= 256;
		vec++;
	}
	*w += *vec;
}

void Initialize(SHA256 *sha)
{
	// Initialize the SHA-256 context.

	sha->datalen = 0;
	sha->bitlen = 0;
	sha->state[0] = 0x6a09e667;
	sha->state[1] = 0xbb67ae85;
	sha->state[2] = 0x3c6ef372;
	sha->state[3] = 0xa54ff53a;
	sha->state[4] = 0x510e527f;
	sha->state[5] = 0x9b05688c;
	sha->state[6] = 0x1f83d9ab;
	sha->state[7] = 0x5be0cd19;
}

void Update(SHA256 *sha, uint8_t *data, uint32_t len)
{
	// Update the hash state with the data.
	uint32_t i;

	for(i = 0; i < len; ++i)
	{
		sha->data[sha->datalen] = *(data + i);
		sha->datalen++;
		if(sha->datalen == BLOCK_BYTES_H)
		{
			Transform(sha, &sha->data[0]);
			sha->bitlen += 512;
			sha->datalen = 0;
		}
	}
}

void Transform(SHA256 *sha, uint8_t *data)
{
	// Compute hash from BLOCK_BYTES_H of data.
	uint32_t a, b, c, d, e, f, g, h, i, t1, t2, sched[BLOCK_BYTES_H];

	for(i = 0; i < 16; i++)
	{
		VecToWord(&sched[i], data);
		data += WORD_BYTES_H;
	}
	for(i = 16; i < BLOCK_BYTES_H; i++)
	{
		sched[i] = sig1(sched[i - 2]) + sched[i - 7] + sig0(sched[i - 15]) + sched[i - 16];
	}
	a = sha->state[0];
	b = sha->state[1];
	c = sha->state[2];
	d = sha->state[3];
	e = sha->state[4];
	f = sha->state[5];
	g = sha->state[6];
	h = sha->state[7];
	for(i = 0; i < BLOCK_BYTES_H; i++)
	{
		t1 = h + SIG1(e) + Ch(e, f, g) + hcon[i] + sched[i];
		t2 = SIG0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	sha->state[0] += a;
	sha->state[1] += b;
	sha->state[2] += c;
	sha->state[3] += d;
	sha->state[4] += e;
	sha->state[5] += f;
	sha->state[6] += g;
	sha->state[7] += h;
}

void Finish(SHA256 *sha, uint8_t *hash)
{
	// Perform final block padding and computations.
	// hash, pointer to a HASH_BYTES_H array of bytes.
	uint32_t i;

	i = sha->datalen;
	if(sha->datalen >= (BLOCK_BYTES_H - LEN_BYTES_H))
	{
		sha->data[i++] = 0x80;
		while(i < BLOCK_BYTES_H)
		{
			sha->data[i++] = 0;
		}
		Transform(sha, sha->data);
		for(i = 0; i < BLOCK_BYTES_H; i++)
		{
			sha->data[i] = 0;
		}
	}
	else
	{
		sha->data[i++] = 0x80;
		while(i < (BLOCK_BYTES_H - LEN_BYTES_H))
		{
			sha->data[i++] = 0;
		}
	}
	sha->bitlen += sha->datalen * 8;
	StoreLength(sha->bitlen, &(sha->data[(BLOCK_BYTES_H - LEN_BYTES_H)]));
	Transform(sha, sha->data);
	WordToVec(sha->state[0], (hash));
	WordToVec(sha->state[1], (hash + 4));
	WordToVec(sha->state[2], (hash + 8));
	WordToVec(sha->state[3], (hash + 12));
	WordToVec(sha->state[4], (hash + 16));
	WordToVec(sha->state[5], (hash + 20));
	WordToVec(sha->state[6], (hash + 24));
	WordToVec(sha->state[7], (hash + 28));
}

void HashData(uint8_t *hash, uint8_t *in, uint32_t inlen)
{
	// Outer SHA hashing function, fills HASH_BYTES_H array pointed to by *hash with results.
	// in, pointer to the data to hash.
	// inlen, the length in bytes of in.
	SHA256 sha;

	Initialize(&sha);
	Update(&sha, in, inlen);
	Finish(&sha, hash);
}

int GetFileHash(char *fn, uint8_t *hash)
{
	// fn, pointer to string of filename to SHA-256
	// hash, pointer to HASH_BYTES_H array to fill with SHA-256
	FILE *fp;
	long fsz;
	size_t br;
	uint8_t *ptemp;

	if((fp = fopen(fn, "rb")) == NULL)
	{
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	fsz = ftell(fp);
	if(fsz < 1)
	{
		fclose(fp);

		return -1;
	}
	rewind(fp);
	if((ptemp = (uint8_t *)malloc(fsz)) == NULL)
	{
		fclose(fp);

		return -1;
	}
	if((br = fread(ptemp, 1, fsz, fp)) != fsz)
	{
		free(ptemp);
		fclose(fp);

		return -1;
	}
	fclose(fp);
	HashData(hash, ptemp, fsz);
	free(ptemp);

	return 0;
}

uint8_t ROBL(uint8_t b, uint8_t r)
{
	// rotate left byte b by r bits
	r %= 8;
	if(!r) return b;
	return (b << r) | (b >> (BYTE_BITS - r));
}

uint8_t ROBR(uint8_t b, uint8_t r)
{
	// rotate right byte b by r bits
	r %= 8;
	if(!r) return b;
	return (b >> r) | (b << (BYTE_BITS - r));
}

// dynamically ordered and generated prekey function.
// DYNGENERATED DYNORDERED J

int GetProcHash(uint8_t *hash)
{
	// get SHA-256 of self.
	// hash, pointer to a HASH_BYTES_H array of bytes.
	pid_t pid;
	char binpath[2048] = {0}, procpath[2048] = {0};
	uint8_t *pbf;
	ssize_t bpl;
	size_t br;
	FILE *fp;
	long fsize;

	pid = getpid();
	snprintf(procpath, 2048, "/proc/%d/exe", pid);
	if((bpl = readlink(procpath, binpath, 2047)) == -1) return -1;
	binpath[bpl] = 0;
	if((fp = fopen(binpath, "rb")) == NULL) return -1;
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	if(fsize < 1)
	{
		fclose(fp);

		return -1;
	}
	rewind(fp);
	if((pbf = (uint8_t *)malloc(fsize)) == NULL)
	{
		fclose(fp);

		return -1;
	}
	if((br = fread(pbf, 1, fsize, fp)) != fsize)
	{
		free(pbf);
		fclose(fp);

		return -1;
	}
	fclose(fp);
	HashData(hash, pbf, br);
	free(pbf);

	return 0;
}

void EncryptBlock(uint8_t *ctblk, uint8_t *ptblk, uint8_t *rkeys, uint8_t *chain)
{
	/* ctblk, pointer to BLOCK_BYTES which receives cipher text output.
	   ptblk, pointer to BLOCK_BYTES of plain text input.
	   rkeys, pointer to RK_BYTES of round key input. 
	   chain, pointer to IV_BYTES of chain vector input/output. */
	int i, j;
	// the current state.
	uint8_t iblock[BLOCK_BYTES];

	// xor the plain text block with the chain vector.
	for(i = 0; i < BLOCK_BYTES; i++)
	{
		iblock[i] = ptblk[i] ^ chain[i];
	}
	j = 0;
	// xor the first round key with the state.
	AddRoundKey(iblock, rkeys, j);
	// encrypt the state.
	while(j < NUM_ROUNDS)
	{
		for(i = 0; i < BLOCK_BYTES; i += WORD_BYTES)
		{
			SubstBytes(&iblock[i]);
		}
		ShiftRows(iblock);
		if(j != (NUM_ROUNDS - 1)) MixColumns(iblock);
		AddRoundKey(iblock, rkeys, ++j);
	}
	memcpy(ctblk, iblock, BLOCK_BYTES);
	memcpy(chain, iblock, BLOCK_BYTES); // CBC
}

void DecryptBlock(uint8_t *ptblk, uint8_t *ctblk, uint8_t *rkeys, uint8_t *chain)
{
	/* ptblk, pointer to BLOCK_BYTES which receives plain text output.
	   ctblk, pointer to BLOCK_BYTES of cipher text input.
	   rkeys, pointer to RK_BYTES of round key input. 
	   chain, pointer to IV_BYTES of chain vector input/output. */
	int i, j;
	// the current and working states.
	uint8_t iblock[BLOCK_BYTES], tblock[BLOCK_BYTES];

	// load the cipher text into the input block.
	memcpy(iblock, ctblk, BLOCK_BYTES);
	// decrypt the state.
	j = NUM_ROUNDS;
	while(j > 0)
	{
		AddRoundKey(iblock, rkeys, j--);
		if(j < (NUM_ROUNDS - 1)) InvMixColumns(iblock);
		InvShiftRows(iblock);
		for(i = 0; i < BLOCK_BYTES; i += WORD_BYTES)
		{
			InvSubstBytes(&iblock[i]);
		}
	}
	AddRoundKey(iblock, rkeys, 0);
	for(i = 0; i < BLOCK_BYTES; i++)
	{
		tblock[i] = iblock[i] ^ chain[i];
	}
	memcpy(chain, ctblk, BLOCK_BYTES); // CBC
	memcpy(ptblk, tblock, BLOCK_BYTES);
}

void KeyExpansion(uint8_t *rkeys, const uint8_t *ukey)
{
	/* rkeys, pointer to array that receives (NUM_ROUNDS + 1) key schedule.
	   ukey, pointer to the key. */
	int i, j, k = 1;
	uint8_t tvec[WORD_BYTES];

	// the first round key is the app-supplied key.
	memcpy(rkeys, ukey, KEY_BYTES);
	// derive the remaining keys from their predecessors.
	for(i = 16; i < RK_BYTES; i += WORD_BYTES)
	{
		// the temporary vector is the last WORD_BYTES bytes.
		for(j = 0; j < WORD_BYTES; j++)
		{
			tvec[j] = rkeys[i - WORD_BYTES + j];
		}
		// perform complex xform every WORD_BYTES rounds.
		if(!(i % KEY_BYTES))
		{
			Rotate(tvec);
			SubstBytes(tvec);
			tvec[0] ^= rcon[k++];
		}
		// xor round key with WORD_BYTES bytes at previous KEY_BYTES offset.
		for(j = 0; j < WORD_BYTES; j++)
		{
			rkeys[i + j] = rkeys[i - KEY_BYTES + j] ^ tvec[j];
		}
	}
}

void Rotate(uint8_t *vec)
{
	/* vec, a vector of WORD_BYTES bytes to be ROL 8 bits in place. */
	uint8_t b;

	b = vec[0];
	vec[0] = vec[1];
	vec[1] = vec[2];
	vec[2] = vec[3];
	vec[3] = b;
}

void SubstBytes(uint8_t *vec)
{
	/* vec, a vector of WORD_BYTES bytes to undergo rsbox substitution. */
	vec[0] = rsbox[vec[0]];
	vec[1] = rsbox[vec[1]];
	vec[2] = rsbox[vec[2]];
	vec[3] = rsbox[vec[3]];
}

void InvSubstBytes(uint8_t *vec)
{
	/* vec, a vector of WORD_BYTES bytes to undergo irsbox substitution. */
	vec[0] = irsbox[vec[0]];
	vec[1] = irsbox[vec[1]];
	vec[2] = irsbox[vec[2]];
	vec[3] = irsbox[vec[3]];
}

void AddRoundKey(uint8_t *vec, uint8_t *rkeys, int rnum)
{
	/* vec, current state, will alter in place.
	   rkeys, pointer to expanded round keys of RK_BYTES bytes.
	   rnum, round key number. */
	int i;

	for(i = 0; i < BLOCK_BYTES; i++)
	{
		vec[i] ^= rkeys[(rnum * KEY_BYTES) + i];
	}
}

void ShiftRows(uint8_t *vec)
{
	/* vec, current state, will alter in place.
	   indexes 0, 4, 8 and 12 unchanged.
	   ROL */
	uint8_t tvec[BLOCK_BYTES];

	memcpy(tvec, vec, BLOCK_BYTES);
	vec[1] = tvec[5];
	vec[2] = tvec[10];
	vec[3] = tvec[15];
	vec[5] = tvec[9];
	vec[6] = tvec[14];
	vec[7] = tvec[3];
	vec[9] = tvec[13];
	vec[10] = tvec[2];
	vec[11] = tvec[7];
	vec[13] = tvec[1];
	vec[14] = tvec[6];
	vec[15] = tvec[11];
}

void InvShiftRows(uint8_t *vec)
{
	/* vec, current state, will alter in place.
	   indexes 0, 4, 8 and 12 unchanged.
	   ROR */
	uint8_t tvec[BLOCK_BYTES];

	memcpy(tvec, vec, BLOCK_BYTES);
	vec[1] = tvec[13];
	vec[2] = tvec[10];
	vec[3] = tvec[7];
	vec[5] = tvec[1];
	vec[6] = tvec[14];
	vec[7] = tvec[11];
	vec[9] = tvec[5];
	vec[10] = tvec[2];
	vec[11] = tvec[15];
	vec[13] = tvec[9];
	vec[14] = tvec[6];
	vec[15] = tvec[3];
}

void MixColumns(uint8_t *vec)
{
	/* matrix transform.
	   vec, current state, will alter in place. */
	uint8_t tvec[BLOCK_BYTES];

	tvec[0] = GM2(vec[0]) ^ GM3(vec[1]) ^ vec[2] ^ vec[3];
	tvec[1] = vec[0] ^ GM2(vec[1]) ^ GM3(vec[2]) ^ vec[3];
	tvec[2] = vec[0] ^ vec[1] ^ GM2(vec[2]) ^ GM3(vec[3]);
	tvec[3] = GM3(vec[0]) ^ vec[1] ^ vec[2] ^ GM2(vec[3]);
	tvec[4] = GM2(vec[4]) ^ GM3(vec[5]) ^ vec[6] ^ vec[7];
	tvec[5] = vec[4] ^ GM2(vec[5]) ^ GM3(vec[6]) ^ vec[7];
	tvec[6] = vec[4] ^ vec[5] ^ GM2(vec[6]) ^ GM3(vec[7]);
	tvec[7] = GM3(vec[4]) ^ vec[5] ^ vec[6] ^ GM2(vec[7]);
	tvec[8] = GM2(vec[8]) ^ GM3(vec[9]) ^ vec[10] ^ vec[11];
	tvec[9] = vec[8] ^ GM2(vec[9]) ^ GM3(vec[10]) ^ vec[11];
	tvec[10] = vec[8] ^ vec[9] ^ GM2(vec[10]) ^ GM3(vec[11]);
	tvec[11] = GM3(vec[8]) ^ vec[9] ^ vec[10] ^ GM2(vec[11]);
	tvec[12] = GM2(vec[12]) ^ GM3(vec[13]) ^ vec[14] ^ vec[15];
	tvec[13] = vec[12] ^ GM2(vec[13]) ^ GM3(vec[14]) ^ vec[15];
	tvec[14] = vec[12] ^ vec[13] ^ GM2(vec[14]) ^ GM3(vec[15]);
	tvec[15] = GM3(vec[12]) ^ vec[13] ^ vec[14] ^ GM2(vec[15]);
	memcpy(vec, tvec, BLOCK_BYTES);
}

void InvMixColumns(uint8_t *vec)
{
	/* matrix transform.
	   vec, current state, will alter in place. */
	uint8_t tvec[BLOCK_BYTES];

	tvec[0] = GM14(vec[0]) ^ GM11(vec[1]) ^ GM13(vec[2]) ^ GM9(vec[3]);
	tvec[1] = GM9(vec[0]) ^ GM14(vec[1]) ^ GM11(vec[2]) ^ GM13(vec[3]);
	tvec[2] = GM13(vec[0]) ^ GM9(vec[1]) ^ GM14(vec[2]) ^ GM11(vec[3]);
	tvec[3] = GM11(vec[0]) ^ GM13(vec[1]) ^ GM9(vec[2]) ^ GM14(vec[3]);
	tvec[4] = GM14(vec[4]) ^ GM11(vec[5]) ^ GM13(vec[6]) ^ GM9(vec[7]);
	tvec[5] = GM9(vec[4]) ^ GM14(vec[5]) ^ GM11(vec[6]) ^ GM13(vec[7]);
	tvec[6] = GM13(vec[4]) ^ GM9(vec[5]) ^ GM14(vec[6]) ^ GM11(vec[7]);
	tvec[7] = GM11(vec[4]) ^ GM13(vec[5]) ^ GM9(vec[6]) ^ GM14(vec[7]);
	tvec[8] = GM14(vec[8]) ^ GM11(vec[9]) ^ GM13(vec[10]) ^ GM9(vec[11]);
	tvec[9] = GM9(vec[8]) ^ GM14(vec[9]) ^ GM11(vec[10]) ^ GM13(vec[11]);
	tvec[10] = GM13(vec[8]) ^ GM9(vec[9]) ^ GM14(vec[10]) ^ GM11(vec[11]);
	tvec[11] = GM11(vec[8]) ^ GM13(vec[9]) ^ GM9(vec[10]) ^ GM14(vec[11]);
	tvec[12] = GM14(vec[12]) ^ GM11(vec[13]) ^ GM13(vec[14]) ^ GM9(vec[15]);
	tvec[13] = GM9(vec[12]) ^ GM14(vec[13]) ^ GM11(vec[14]) ^ GM13(vec[15]);
	tvec[14] = GM13(vec[12]) ^ GM9(vec[13]) ^ GM14(vec[14]) ^ GM11(vec[15]);
	tvec[15] = GM11(vec[12]) ^ GM13(vec[13]) ^ GM9(vec[14]) ^ GM14(vec[15]);
	memcpy(vec, tvec, BLOCK_BYTES);
}

uint8_t GM2(uint8_t b)
{
	// GF(2**8) mult by 2.
	uint8_t t;

	if(b & 0x80)
	{
		t = b << 1;
		t ^= 0x1b;
	}
	else
	{
		t = b << 1;
	}

	return t;
}

uint8_t GM3(uint8_t b)
{
	// GF(2**8) mult by 3.

	return GM2(b) ^ b;
}

uint8_t GM9(uint8_t b)
{
	// GF(2**8) mult by 9.

	return GM2(GM2(GM2(b))) ^ b;
}

uint8_t GM11(uint8_t b)
{
	// GF(2**8) mult by 11.

	return GM2(GM2(GM2(b)) ^ b) ^ b;
}

uint8_t GM13(uint8_t b)
{
	// GF(2**8) mult by 13.

	return GM2(GM2((GM2(b) ^ b))) ^ b;
}

uint8_t GM14(uint8_t b)
{
	// GF(2**8) mult by 14.

	return GM2(GM2((GM2(b) ^ b)) ^ b);
}

// dynamically ordered and generated DB key function.
// DYNGENERATED DYNORDERED K

int DisableEcho(struct termios *oflags)
{
	struct termios nflags;

	nflags = *oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;
	nflags.c_lflag |= ICANON;
	if(tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) return -1;

	return 0;
}

int EnableEcho(struct termios *oflags)
{
	if(tcsetattr(fileno(stdin), TCSANOW, oflags) != 0) return -1;

	return 0;
}

void FlushStdIn()
{
	__fpurge(stdin);
}

// END OF FILE.

END_OF_TEMPLATE
	return @template;
}


