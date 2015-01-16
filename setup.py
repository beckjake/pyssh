
from distutils.core import setup

setup(name='pyssh',
      version=0.1,
      description='A python SSH2 library',
      author='Jacob Beck',
      author_email='beckjake@gmail.com',
      packages=['pyssh'],
      install_requires=[
        "future>=0.14.3",
        "cryptography>=0.6.1",
        "singledispatch>=3.4.0.3"
        ]
)
