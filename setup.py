from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(name='filesig',
      version='0.3.0-1',
      description="Python command on top of 'poppler-utils' and 'openssl' used to verify file signatures",
      long_description=readme(),
      classifiers=['Development Status :: 5 - Production/Stable',
                  'License :: OSI Approved :: BSD License',
                  'Programming Language :: Python :: 2',
                  'Programming Language :: Python :: 3'],
      url='https://github.com/peppelinux/FileSignatureValidator',
      author='Giuseppe De Marco',
      author_email='giuseppe.demarco@unical.it',
      license='BSD',
      scripts=['filesig/filesig.py'],
      packages=['filesig'],
      install_requires=[],
     )
