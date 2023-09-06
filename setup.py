import setuptools
import os
import configparser

setup_config = configparser.ConfigParser()
setup_config.read('setup.cfg')

requirements = list()
requirements_file = 'requirements.txt'
if os.access(requirements_file, os.R_OK):
    with open(requirements_file, 'r') as requirements_file_pointer:
        requirements = requirements_file_pointer.read().split()
setuptools.setup(
    scripts=['rc_push/rc_push.py'],
    author="Antonio J. Delgado",
    version=setup_config['metadata']['version'],
    name=setup_config['metadata']['name'],
    author_email="",
    url="",
    description="Push RocketChat notifications to a ntfy service",
    license="GPLv3",
    install_requires=requirements,
    #keywords=["my", "script", "does", "things"]
)
