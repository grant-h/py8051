import os
import urllib2
import subprocess
import sys
import shutil
import glob
from distutils.errors import LibError
from distutils.core import setup
from distutils.command.build import build as _build
from setuptools.command.bdist_egg import bdist_egg as _bdist_egg

if sys.platform == 'darwin':
    library_file = "libpy8051.dylib"
else:
    library_file = "libpy8051.so"

def _build_8051():
    e = os.environ.copy()
    if subprocess.call(['make'], cwd='py8051_c', env=e) != 0:
        raise LibError("Unable to build py8051-static.")

def _shuffle_files():
    shutil.rmtree('py8051/lib', ignore_errors=True)
    os.mkdir('py8051/lib')

    shutil.copy(os.path.join('py8051_c', library_file), 'py8051/lib')

class build(_build):
    def run(self):
        self.execute(_build_8051, (), msg="Building py8051-static")
        self.execute(_shuffle_files, (), msg="Copying libraries and headers")
        _build.run(self)
cmdclass = { 'build': build }

class bdist_egg(_bdist_egg):
    def run(self):
        self.run_command('build')
        _bdist_egg.run(self)
cmdclass['bdist_egg'] = bdist_egg

try:
    from setuptools.command.develop import develop as _develop
    class develop(_develop):
        def run(self):
            self.execute(_build_8051, (), msg="Building py8051-static")
            self.execute(_shuffle_files, (), msg="Copying libraries and headers")
            _develop.run(self)
    cmdclass['develop'] = develop
except ImportError:
    print "Proper 'develop' support unavailable."

setup(
    name="py8051", version='0.1.1', description="A Python interface to an 8051 disassembler.",
    keywords=["disassembler", "8051"],
    author = 'Grant Hernandez',
    author_email = 'grant.h.hernandez@gmail.com',
    url = 'https://github.com/grant-h/py8051',
    download_url = 'https://github.com/grant-h/py8051/archive/0.1.tar.gz',

    packages=['py8051'],
    cmdclass=cmdclass,
    install_requires=[ 'pycparser', 'cffi>=1.0.3'],
    setup_requires=[ 'pycparser', 'cffi>=1.0.3' ],
    include_package_data=True,
    package_data={
        'py8051': ['lib/*']
    }
)
