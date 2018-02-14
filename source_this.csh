#!/bin/csh

sudo -H pip install --upgrade pip virtualenv

virtualenv --no-site-packages -p python2 venv
source venv/bin/activate.csh

pip install -r pip_requirements.txt
setenv PYTHONPATH `pwd`
