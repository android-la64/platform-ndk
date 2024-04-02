# Building the NDK

The latest version of this document is available at
https://android.googlesource.com/platform/ndk/+/master/docs/Building.md.

Both Linux and Windows NDKs are built on Linux machines. Windows host binaries
are cross-compiled with MinGW.

Building the NDK for Mac OS X requires at least 10.13.

## Prerequisites

The first thing you need is the AOSP NDK repository. If you're new to using repo
and gerrit, see [repo.md](repo.md) for tips. If you're already familiar with how
to use repo and gerrit from other Android projects, you already know plenty :)

Check out the branch `master-ndk`. Do this in a new directory.

```bash
# For non-Googlers:
repo init -u https://android.googlesource.com/platform/manifest -b master-ndk --partial-clone

# Googlers, follow http://go/repo-init/master-ndk (select AOSP in the Host menu,
# and uncheck the box for the git superproject). At time of writing, the correct
# invocation is:
repo init -u \
    sso://android.git.corp.google.com/platform/manifest -b master-ndk --partial-clone
```

If you wish to rebuild a given release of the NDK, the release branches can also
be checked out. They're named `ndk-release-r${RELEASE}` for newer releases, but
`ndk-r{RELEASE}-release` for older releases. For example, to check out the r19
release branch, use the `-b ndk-release-r19` flag instad of `-b master-ndk`.

Linux dependencies are listed in the [Dockerfile]. You can use docker to build
the NDK:

```bash
docker build -t ndk-dev infra/docker
docker run -it -u $UID -v `realpath ..`:/src -w /src/ndk ndk-dev ./checkbuild.py
```

Building on Mac OS X has similar dependencies as Linux, but also requires Xcode.

Running tests requires that `adb` is in your `PATH`. This is provided as part of
the [Android SDK].

[Dockerfile]: ../infra/docker/Dockerfile
[Android SDK]: https://developer.android.com/studio/index.html#downloads

## Python environment setup

To set up your environment to use the correct versions of Python and Python
packages, install [Poetry](https://python-poetry.org/) and then do the
following.

Whenever you set up a new NDK tree (after a fresh `repo init`, for example),
configure the project to use our prebuilt Python instead of your system's. If on
Mac, be sure to use the darwin-x86 version instead.

```bash
poetry env use ../prebuilts/python/linux-x86/bin/python3
```

The first time, and also anytime you sync because there might be new or updated
dependencies, install the NDK dependencies to the virtualenv managed by poetry.

```bash
poetry install
```

Note: If `poetry install` hangs on Linux, try
`PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring poetry install`.

Spawn a new shell using the virtualenv that Poetry created. You could instead
run NDK commands with the `poetry run` prefix (e.g. `poetry run
./checkbuild.py`), but it's simpler to just spawn a new shell. Plus, if it's in
your environment your editor can use it.

```bash
poetry shell
```

### macOS workarounds

On macOS you may not be able to use the Python that is in prebuilts because it
does not support the ssl module (which poetry itself needs). Until the Python
prebuilt includes that module, do the following to use a different Python:

First time setup: ensure that you have pyenv installed. You may need to install
homebrew (http://go/homebrew for Googlers, else https://brew.sh/).

```
$ brew update && brew upgrade pyenv
```

Then set up your tree to use the correct version of Python. This setting will
apply to the directory it is run in, so you will need to do it per NDK tree.

```
# From the //ndk directory of your NDK tree:
$ ../prebuilts/python/darwin-x86/bin/python3 --version
Python 3.11.4
# We don't need to match the version exactly, just the major/minor version.
$ pyenv install 3.11:latest
$ pyenv local 3.11
$ python --version
Python 3.11.8
$ poetry env use 3.11
poetry install
```

Each time the NDK updates to a new version of Python, you'll need to repeat
those steps. You may also need to remove the old poetry environment
(`poetry env list` to get the name, `poetry env remove` to remove it).

`checkbuild.py` and `run_tests.py` will complain when you try to use a Python
that doesn't come from prebuilts by default. To suppress that, pass
`--permissive-python-environment` when using those tools in this environment.

## Build

### For Linux or Darwin

```bash
$ python checkbuild.py
```

If you get an error like the following:

```
Expected python to be $NDK_SRC/prebuilts/python/$HOST/bin/python3.9, but is ~/.cache/pypoetry/virtualenvs/$VENV/bin/python (/usr/bin/python3.9).
```

Your Poetry virualenv was misconfigured. It seems that `poetry env use` will not
replace an existing virtualenv of the same major/minor version, so if you ran
any poetry commands before `poetry env use`, your environment needs to be
deleted and recreated.

```bash
$ poetry env remove $VENV
$ poetry env use ../prebuilts/python/linux-x86/bin/python3
$ poetry install
```

If you get an error like the following:

```
Expected python to be $NDK_SRC/prebuilts/python/linux-x86/bin/python3.9, but is /usr/bin/python (/usr/bin/python3.9).
```

You ran checkbuild.py outside the poetry environment. Ensure that you've done
the first time setup (`poetry env use` and `poetry install`, as above), then
either run `poetry shell` to enter a new shell with the correct environment, or
use `poetry run checkbuild.py`.

If you get errors from the pythonlint task but it appears to only affect your
machine, one of the linters you have installed is probably not the correct
version. Run `poetry install` to sync your environment with the expected
versions.

### For Windows, from Linux

```bash
$ python checkbuild.py --system windows64
```

`checkbuild.py` will also build all of the NDK tests. This takes about 3x as
long as building the NDK itself, so pass `--no-build-tests` to skip building the
tests if you're iterating on build behavior or plan to rebuild only specific
tests. Tests can be built later with `python run_tests.py --rebuild`.

Note: The NDK's build and test scripts are implemented in Python 3 (currently
3.9). `checkbuild.py` will use a prebuilt Python, but `run_tests.py` does not do
this yet. `run_tests.py` also can be run outside of a complete development
environment (as it is when it is run on Windows), so a Python 3.9 virtualenv is
recommended.

## Packaging

Packaging uses `zip -9` so is extremely time consuming and disabled by default.
Use the `--package` flag to force packaging locally. This is not required for
local development and only needs to be used when testing packaging behavior.
