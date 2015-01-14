pyssh
=====

An SSH2 library in python, making use of Cryptography.io.


What works:
-----------
    - Some tests
    - Some message packing/unpacking code
    - 99%+ test coverage

What doesn't work in order of likelihood to get fixed:
------------------------------------------------------
    - The actual protocol
    - Security
    - Stability
    - Documentation


Support Goal:
-------------
    Python 3.3+, Python 2.7+, pypy on Linux/Mac/Win


Requirements:
-------------
    - everything listed in install_requires in setup.py
    - for development, everything in etc/dev-requirements.txt


Tests/Development:
------------------
    - make yourself a new virtualenv
    - check out from github and cd into the directory with this file.
    - `pip install -e . -r etc/dev-requirements.txt`
    - To run tests, `python run_tests.py`
    - To run pylint, `pylint --rcfile=etc/pylintrc pyssh`


Licensing:
----------

This is licensed as CC0, a license I love very much. You can read about it at
https://creativecommons.org/publicdomain/zero/1.0/ or read the "legal code" in
the etc/LICENSE file.

