"""
AWS Lambda function to receive GitHub webhooks from API gateway and relay them to an EC2 instance
"""
from setuptools import find_packages, setup

dependencies = ['boto3', 'requests', 'httpretty']

setup(
    name='lambda-webhook',
    version='0.2.0',
    url='https://github.com/pristineio/lambda-webhook',
    license='BSD',
    author='John Schwinghammer',
    author_email='john+githubsource@pristine.io',
    description='AWS Lambda function to receive GitHub webhooks from API gateway and relay them to an EC2 instance',
    long_description=__doc__,
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=dependencies,
    entry_points={
        'console_scripts': [
            'lambda-webhook-sqs=lambdawebhook.sqs:cmd',
        ],
    },
    classifiers=[
        # As from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        # 'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
        # 'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Software Development :: Build Tools',
    ]
)
