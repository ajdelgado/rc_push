import setuptools
import os

requirements = list()
requirements_file = 'requirements.txt'
if os.access(requirements_file, os.R_OK):
    with open(requirements_file, 'r') as requirements_file_pointer:
        requirements = requirements_file_pointer.read().split()
setuptools.setup(
    scripts=['rc_push/rc_push.py'],
    author="Antonio J. Delgado",
    version='0.0.5',
    name='rc_push',
    author_email="",
    url="",
    description="__description__",
    license="GPLv3",
    install_requires=requirements,
    #keywords=["my", "script", "does", "things"]
)
