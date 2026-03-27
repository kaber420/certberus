#!/bin/bash
# Proyecto RCS (YuxiCA) - Script de Inicio del Nodo Local
echo "Iniciando Certberus con Sello Yuxi (Federación RCS)..."
export PYTHONPATH=src
./venv/bin/python3 -m certberus.cli serve --host 127.0.0.1 --port 8080
