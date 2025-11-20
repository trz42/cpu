# CPU - The next-generation EESSI build-and-deplot bot

<img width="128" height="128" alt="Image"
     src="https://github.com/user-attachments/assets/6b2d7121-fe49-40c8-b3ed-b935e537853c"
     align="left" style="margin-right: 20px; margin-bottom: 10px;" />

<br />

CPU is the next-generation EESSI build-and-deploy bot. It tries to achieve three main
objectives:
- refactor the design of the first-generation EESSI build-and-deploy bot towards a unified,
  multi-threaded and customizable architecture,
- prepare for more security-focused scenarios, so it can be employed by a wide range of users
  and establish higher trust on what it builds, _and_
- improve user-friendliness concerning installation, configuration and monitoring.

Below, you find information on how to set up the build environment, test changes and create
a new release.

<br />

[![Lint](https://github.com/trz42/cpu/actions/workflows/lint.yml/badge.svg)](https://github.com/username/cpu/actions/workflows/lint.yml)
[![Tests](https://github.com/trz42/cpu/actions/workflows/test.yml/badge.svg)](https://github.com/username/cpu/actions/workflows/test.yml)
[![codecov](https://codecov.io/github/trz42/cpu/graph/badge.svg?token=ZE4FE8WSVJ)](https://codecov.io/github/trz42/cpu)
![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![License GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-green.svg)

## Installation with local tagging

### Set up development environment

#### Steps to perform once

```bash
# clone repo
git clone git@github.com:trz42/cpu.git
python3 -m vtestcpu
source vtestcpu/bin/activate
python3 -m pip install --upgrade pip
```

#### Tagging and installing a version

```bash
# if venv not activated yet
source vtestcpu/bin/activate
cd cpu
git tag v0.0.1-alpha
git tag
pip3 install -e ".[dev]"
```

#### Testing the installed version

```bash
pip show cpu
python -c "import cpu; print(cpu.__version__)"
```

If the last command fails, try

```bash
python -c "from importlib.metadata import version; print(version('cpu'))"
```

#### Debugging tags

```bash
git describe --tags
git log --oneline --decorate
```

#### After a change: re-tag and re-install

```bash
git tag -d v0.0.1-alpha   # Delete old tag
git tag v0.0.1-alpha      # Tag current commit
pip install -e ".[dev]"   # Reinstall
```

## Run unit tests

- Run all tests

  ```bash
  python3 -m venv ../vpytest
  python3 -m pip install --upgrade pip
  source ../vpytest/bin/activate
  pip3 install -e ".[dev]"
  pytest
  deactivate
  ```

## Steps to prepare a release

1. Create branch for release from develop

   ```bash
   git checkout develop
   git pull
   git checkout -b release_vX.Y.Z origin/develop
   ```

2. Update `CHANGELOG.md` for the release using the template below
   > [!NOTE]
   > The format of the first line including two hashmarks, version in brackets
   > is important for automatic creation of releases!

   ```bash
   ## [X.Y.Z] - 2025-11-15

   ### Added
   - Initial package structure
   - Basic package installation support
   - Version management with setuptools-scm

   ### Changed
   - none

   ### Fixed
   - none
   ```

3. Commit and push the changes

   ```bash
   git add CHANGELOG.md
   git commit -m "update CHANGELOG.md for release vX.Y.Z
   git push origin release_vX.Y.Z
   ```

4. Create PR on GitHub
   - Open [https://github.com/trz42/cpu/pulls](https://github.com/trz42/cpu/pulls)
   - Create a pull request to merge the updated `CHANGELOG.md` into the `develop` branch
   - Title: Updated CHANGELOG.md for release vX.Y.Z
   - Description: copy the contents of the CHANGELOG.md for this release

5. Get PR merged
   - After it got merged update local git repository

     ```bash
     git checkout develop
     git pull
     ```

   - Cleanup branch for release locally and remotely

     ```bash
     git branch -d release_vX.Y.Z
     git push origin :release_vX.Y.Z
     git branch -r
     ```

6. Create PR to merge develop into main
   - Open [https://github.com/trz42/cpu/compare/main...develop](https://github.com/trz42/cpu/compare/main...develop)
   - Click on "Create pull request" to start creating a new pull request
   - Title: Release vX.Y.Z
   - Description: contents of `CHANGELOG.md` for this release

7. Get PR merged

8. Checkout main, pull in changes, tag it and push tag to GitHub

   ```bash
   git checkout main
   git pull
   git tag
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   > [!NOTE]
   > See below for instructions to manually create the release including packages in case the CI fails.

9. Try to install locally from GitHub and run some tests

   ```bash
   python3 -m venv ../vtestinstall
   source ../vtestinstall/bin/activate
   python3 -m pip install --upgrade pip
   pip install https://github.com/trz42/cpu/releases/download/vX.Y.Z/cpu-X.Y.Z-py3-none-any.whl
   pip show cpu
   python -c "import cpu; print(cpu.__version__)"
   deactivate
   ```

   (Optionally) cleanup virtual environment: `rm -rf ../vtestinstall`

### Creating release manually

If the step in which one pushes a tag to GitHub does not result in the automatic creation of a release,
perform the following steps to create it manually.

1. Build package locally

   ```bash
   python3 -m venv ../vbuildcpu
   source ../vbuildcpu/bin/activate
   python3 -m pip install --upgrade pip
   pip install -e ".[dev]"
   python -m build
   ls dist
   deactivate
   ```

   (Optionally) cleanup virtual environment: `rm -rf ../vbuildcpu`

2. Create release on GitHub: use pushed tag, copy changelog and upload whl and tar.gz
   - Open [https://github.com/trz42/cpu/releases/new](https://github.com/trz42/cpu/releases/new)
   - Select the release created above
   - Title: vX.Y.Z
   - Description: contents of `CHANGELOG.md` for this release
   - Upload `cpu-X.Y.Z-py3-none-any.whl` and `cpu-X.Y.Z.tar.gz` from dist directory
