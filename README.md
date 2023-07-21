
# pySigma crowdsec Backend


This is a **WIP** crowdsec backend for pySigma. It provides the package `sigma.backends.crowdsec` with the `crowdsecBackend` class.

It supports the following output formats:

* default: unused
* default_yaml: try to generate a valid crowdsec scenario (yaml) from sigma rule


# Testing

```
poetry install
poetry poetry run python3 sigma/tester.py .../proc_creation_win_7zip_exfil_dmp_files.yml
```

# Current status

Supported:
 - `windows/process_creation`
 - `web/webserver_generic`
