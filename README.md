# Automatic FOrensics Tool

The Automatic FOrensics Tool (AFOT) is an automation tool build in Python and used for Windows Forensics in order to combine the following tools:
- AnalyzePESig (http://didierstevens.com/files/software/AnalyzePESig_V0_0_0_2.zip)
- National Software Reference Library reduced set (http://www.nsrl.nist.gov/RDS/rds_2.52/rds_252m.zip)
- NSRL Tool (http://didierstevens.com/files/software/nsrl_V0_0_2.zip)
- VirusTotal Search Tool (http://didierstevens.com/files/software/virustotal-search_V0_1_2.zip)


## Requirements

The script makes use of Python version 2.7, but it will most likely work with Python 3.
You will need to have **PIP** installed in your system. Please see [python docs](https://pip.pypa.io/en/stable/installing/) for details.

You should have your own a VirusTotal api key. Just create an account in VirusTotal website and grab the api key. Then add it as the `__VIRUSTOTALAPIKEY__` value.


## Usage

Just run `python afot.py` in your terminal.


## Procedure

So the procedure is pretty straight-forward:
* The user provides the path, which will be used to analyze all the executables included in those folders/subfolders.
* **AnalyzePESig** looks for signed executables, whom certificate will soon be revoked.
* **AFOT** will collect all the non-signed executables and cross-check them with NSRL's hashset database, using the **NSRL** tool.
* Last but not least, if any hashes were found to be in NSRL's hashset database too, we cross-check those hashes with **VirusTotal**, using the VirusTotal Search tool.


## Contributing

Please see [CONTRIBUTING](https://github.com/harris21/afot/blob/master/CONTRIBUTING.md) for details.


## License

The MIT License (MIT). Please see [License File](https://github.com/harris21/afot/blob/master/LICENSE) for more information.
