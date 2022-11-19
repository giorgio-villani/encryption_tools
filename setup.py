from setuptools import setup, find_packages

setup(
    name='EncryptionTools',
    version='0.1.0',
    author='Giorgio Villani',
    packages=find_packages(),
    scripts=['bin/__init__.py','bin/key_generator.py'],
    url='http://pypi.python.org/pypi/EncryptionTools/',
    # license='LICENSE.txt',
    description='Misc tools for encryption',
    long_description=open('README.md').read(),
    install_requires=[
        "cryptography >= 1.1.1",
    ],
)