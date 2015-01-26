
from distutils.core import setup
import sys

install_requires = [
    "future>=0.14.3",
    "cryptography>=0.7.2"
]
if sys.version_info < (3,4):
    install_requires.extend([
        "enum34>=1.0.4"
    ])

setup(name='pyssh',
      version=0.1,
      description='A python SSH2 library',
      author='Jacob Beck',
      author_email='beckjake@gmail.com',
      packages=['pyssh'],
      install_requires=install_requires
)
