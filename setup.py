from setuptools import setup, find_packages

setup(
      name='ctf',
      version='0.1',
      description='ctf helper library',
      url='https://github.com/hyperreality/ctf',
      author='hyperreality',
      author_email='lt@codewordsolver.com',
      packages=find_packages(),
      package_data={'': ['words.txt']},
      include_package_data=True,
      install_requires=['gmpy2', 'pycryptodome', 'pyOpenSSL'],
)

