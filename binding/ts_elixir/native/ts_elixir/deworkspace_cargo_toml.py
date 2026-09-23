#!/usr/bin/env python3

"""
Generate a new Cargo.toml suitable for publishing to hex.pm by stripping unnecessary keys
and references to the cargo workspace.

Usage:

    $ deworkspace_cargo_toml.py --root ../../../Cargo.toml < Cargo.toml

"""

import tomllib
import tomli_w
import argparse
import sys

ALLOWED_PACKAGE_KEYS = {'name', 'version', 'edition', 'license'}


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--root', required=True, help='workspace root Cargo.toml')
    parser.add_argument('--repo_sha',
                        help='replace repo dep versions with git dep at specified sha')

    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.root, 'rb') as f:
        roottoml = tomllib.load(f)

    cargotoml = tomllib.load(sys.stdin.buffer)

    if 'lints' in cargotoml:
        del cargotoml['lints']

    if 'dev-dependencies' in cargotoml:
        del cargotoml['dev-dependencies']

    cargotoml['package'] = {k: v for k, v in cargotoml['package'].items() if
                            k in ALLOWED_PACKAGE_KEYS}

    for k in ALLOWED_PACKAGE_KEYS:
        value = cargotoml['package'][k]

        if type(value) == dict and value['workspace'] is True:
            cargotoml['package'][k] = roottoml['workspace']['package'][k]

    wksp_deps = roottoml['workspace']['dependencies']

    for name in ['dependencies', 'build-dependencies']:
        if name not in cargotoml:
            continue

        for dep in list(cargotoml[name].keys()):
            value = cargotoml[name][dep]

            if type(value) == dict and value.get('workspace') is True:
                if args.repo_sha and (dep.startswith('tailscale') or dep.startswith('ts_')):
                    value['git'] = f'https://github.com/tailscale/tailscale-rs'
                    value['rev'] = args.repo_sha
                else:
                    wksp_dep = wksp_deps[dep]

                    if type(wksp_dep) == str:
                        value['version'] = wksp_dep
                    elif type(wksp_dep) == dict:
                        value['version'] = wksp_dep['version']
                    else:
                        raise ValueError(f'dep "{dep}" has unknown dep format in workspace Cargo.toml')

                del value['workspace']

    tomli_w.dump(cargotoml, sys.stdout.buffer)


if __name__ == '__main__':
    main()
