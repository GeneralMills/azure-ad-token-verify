import io
import os

from setuptools import setup

dir = os.path.dirname(__file__)

with io.open(os.path.join(dir, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='aad-token-verify',
    version='0.1.1',
    description='A python utility library to verify an Azure Active Directory OAuth token',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/GeneralMills/azure-ad-token-verify',
    author=['Daniel Thompson'],
    author_email='daniel.thompson2@genmills.com ',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    python_requires='>=3.6',
    install_requires=[
        'requests>=2.25.1,<3',
        'PyJWT>=2.1.0,<3',
        'cryptography>=3.3.2<4',
        'cachetools>=4.2.2,<5'
    ],
    keywords='azure ad token oauth verify jwt',
    packages=['aad_token_verify'],
)
