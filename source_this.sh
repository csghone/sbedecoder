#!/bin/bash

sudo -H pip install --upgrade pip virtualenv

virtualenv --no-site-packages -p python2 venv
source venv/bin/activate

pip install -r pip_requirements.txt

export PYTHONPATH=`pwd`
