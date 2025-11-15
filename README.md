# CPU bot -- The next-generation EESSI build-and-deplot bot

<img width="128" height="128" alt="Image" src="https://github.com/user-attachments/assets/6b2d7121-fe49-40c8-b3ed-b935e537853c" align="left" style="margin-right: 20px; margin-bottom: 10px;" />

<br />

The CPU bot is the next-generation EESSI build and deploy bot. This issue tracks the creation of the initial directory structure and skeleton files for the CPU bot - the refactored EESSI build and deploy bot with unified multi-threaded architecture.

<br />

# Installation with local tagging

## Set up development environment
### Steps to performe once
```bash
# clone repo
git clone git@github.com:trz42/cpu.git
python3 -m vtestcpu
source vtestcpu/bin/activate
python3 -m pip install --upgrade pip
```
### Tagging and installing a version
```bash
# if venv not activated yet
source vtestcpu/bin/activate
cd cpu
git tag v0.0.1-alpha
git tag
pip3 install -e ".[dev]"
```
### Testing the installed version
```bash
pip show cpu
python -c "import cpu; print(cpu.__version__)"
```
If the last command fails, try
```bash
python -c "from importlib.metadata import version; print(version('cpu'))"
```
### Debugging tags
```bash
git describe --tags
git log --oneline --decorate
```
### After a change: re-tag and re-install
```bash
git tag -d v0.0.1-alpha   # Delete old tag
git tag v0.0.1-alpha      # Tag current commit
pip install -e ".[dev]"   # Reinstall
```
