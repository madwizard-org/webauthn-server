# WebAuthn Relying Party server library for PHP

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/madwizard-org/webauthn-server/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/madwizard-org/webauthn-server/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/madwizard-org/webauthn-server/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/madwizard-org/webauthn-server/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/madwizard-org/webauthn-server/badges/build.png?b=master)](https://scrutinizer-ci.com/g/madwizard-org/webauthn-server/build-status/master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Current state

Pretty stable but the API may still change slightly until the 1.0 release.

## Goal

This library aims to implement the relying party server of the WebAuthn specification in PHP. Important goals are:

- Implement the level 1 WebAuthn specification
- Good quality, secure and maintainable code
- Easy to use for the end-user


## Installation

Installation via composer:
```bash
composer require madwizard/webauthn
```

## Supported features

- > PHP 7.2
- FIDO conformant library
- Attestation types:
    - FIDO U2F
    - Packed
    - TPM
    - Android SafetyNet
    - Android Key
    - Apple
    - None
    - Optional 'unsupported' type to handle future types
- Metadata service support
- Validating metadata
- Extensions:
    - appid


## Usage

The library is still in development so documentation is limited. The general pattern to follow is:

1. Implement `CredentialStoreInterface` (you will need `UserCredential` or your own implementation of `UserCredentialInterface`)
2. Create an instance of `RelyingParty` and use the `ServerBuilder` class to build a server object:
```php
$server = (new ServerBuilder())
    ->setRelyingParty($rp)
    ->setCredentialStore($store)
    ->build();
```
3. Use `startRegistration`/`finishRegistration` to register credentials. Be sure to store the temporary `AttestationContext` server side!
4. and `startAuthentication`/`finishAuthentication` to authenticate. Be sure to store the temporary `AssertionContext` server side!

## Resources

[WebAuthn specification](https://www.w3.org/TR/webauthn/)
