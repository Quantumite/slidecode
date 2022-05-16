from setuptools import setup, find_packages

setup(
    name = "slidecode",
    py_modules=['slidecode'],
    packages=find_packages(where='src'),
    package_dir={'':'src'},
)