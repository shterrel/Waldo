# Waldo Command Line Tool

## Install

```
git clone https://github.com/rackerlabs/waldo-client.git
cd waldo-client
pip install -r requirements.txt
python setup.py install
```

## Usage

### Authentication

There are many ways to provide user credentials:

* Environment variables
* Command-line arguments
* User keyring
* [Hammertime](https://github.rackspace.com/matt-martz/hammertime) cached
  token in `~/.hammertime/cache/session`
* Waldo cached token in `~/.waldo_cache`

Regardless of the method that is used, `waldo` will create its own local cache
of the token in `~/.waldo_cache` that is used to speed up subsequent commands.

#### Environment Variables

```
$ export WALDO_USERNAME=bob.smith
$ read -s WALDO_PASSWORD
$ waldo version
```

#### Command-line Arguments

```
$ waldo --username bob.smith --password imnottellingyou list 547495
```

#### Hammertime Cache File

If `~/.hammertime/cache/session` is detected the user token will read from that
file. The file does not keep track of the token expiration timestamp so there
is some risk that a stale token could be used.

The username that is stored in the cache file will be ignored.

#### Waldo Cache File

If `~/.waldo_cache` exists and it contains a token that has not yet expired the
token will be reused. Waldo rewrites this file after every execution with the
token value that it obtains through other methods (e.g. command-line argument,
read from Hammertime cache).

#### User Keyring

Waldo reads from system keyring for the paths `waldoc/username`,
`waldoc/password`, and `waldoc/token`. Using keyring for your username and
password isn't a terrible idea but tokens change too often for this to be the
recommended storage method.

* [OSX help with Keyring](http://www.macworld.com/article/2013756/how-to-manage-passwords-with-keychain-access.html)
* [Linux help with Keyring](https://wiki.gnome.org/action/show/Projects/GnomeKeyring)


### Discovery Search

```
$ waldo list waldotest.cldsrvr.com
$ waldo list 547495
```

### Discovery Details

```
$ waldo show fe70803330604458989c6e87a9b0a737
$ waldo show fe70803330604458989c6e87a9b0a737 --include-system-info
```

### Create a New Discovery

```
$ waldo discover waldotest.cldsrvr.com
$ waldo discover waldotest.cldsrvr.com --dont-login
$ waldo discover 547495
```

### Version

```
$ waldo version
Client version: 0.0.1
Server version: 0.2.3
```

## Hacking

### Setup

```
git clone https://github.com/your-username/waldo-client.git
cd waldo-client
pip install -r requirements.txt
pip install -r test-requirements.txt
python setup.py develop
```

### Testing

The `testr` command will execute all of the unit tests.

```
testr init # only needed once
testr run
```
