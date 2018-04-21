# psl
Protected Script Launcher, version 1.1.0

Offers an improvement in storing sensitive script parameters, such as
authentication credentials, over traditional methods.  Automated tasks that
need to run without user interaction face a challenge of where and how to
store keys or credentials.  The usual methods of including credentials within
scripts is to either store them in plain text, obfuscate them in some
reversible form such as base64 or rot13, use encoding/encryption methods where
access to the decryption material may be trivial even if stored off-host, or
by protecting scripts simply with file permissions.  Approaches that use key
retrieval methods at run-time from a key management system (KMS) may add
complexity to the task of retrieving secrets but ultimately do not solve the
problem, they merely relocate the problem.  Systems employing trusted host or
application level mutual authentication and key encrypting keys (KEKs) often
have a weak element which can be used to circumvent security; given enough
analysis, time and effort those weaknesses can be exploited.

PSL does not introduce a revolutionary method to automated key retrieval but
it does add several factors that improve on the storage and execution of
protected scripts.  View the comments in the perl script (psl.pl) for more
information and how to use.
