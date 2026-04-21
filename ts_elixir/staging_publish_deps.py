#!/usr/bin/env python

"""
staging.hex.pm generally doesn't have our deps uploaded.
Try to upload them from our local dep cache so that we can try a staging push.
"""

import shutil
import sys
import pathlib
import os
import shlex
import subprocess

if os.name != 'nt':
    MIX_EXE = 'mix'
else:
    MIX_EXE = 'mix.bat'


def try_publish(path: pathlib.Path):
    def mix_call(args, ok_output=None):
        ret = subprocess.run(shlex.split(f'{MIX_EXE} {args}'), cwd=path, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        sys.stderr.buffer.write(ret.stderr)
        sys.stdout.buffer.write(ret.stdout)

        if ok_output and (ok_output in ret.stderr or ok_output in ret.stdout):
            return

        ret.check_returncode()

    print(f'try publish {path.name}')
    mix_call('deps.get')
    mix_call('deps.compile')
    mix_call('hex.publish package --yes', ok_output=b'must include the --replace flag')
    print(f'published {path.name}')

    try:
        shutil.rmtree(path.joinpath('_build'))
    except FileNotFoundError:
        pass

    try:
        shutil.rmtree(path.joinpath('deps'))
    except FileNotFoundError:
        pass


def main():
    os.environ['MIX_ENV'] = 'prod'

    if os.environ.get('HEX_API_URL') is None:
        print('setting HEX_API_URL to staging')
        os.environ['HEX_API_URL'] = 'https://staging.hex.pm/api'

    if not os.environ.get('HEX_API_KEY'):
        print('warning: HEX_API_KEY unset')

    this_path = pathlib.Path(__file__)
    os.chdir(this_path.parent.joinpath('deps'))

    paths = set()

    for pat in pathlib.Path.cwd().glob('*'):
        if not pat.is_dir():
            continue

        if not pat.joinpath('mix.exs').exists():
            continue

        paths.add(pat)
        print(pat.name)

    while True:
        any_success = False

        for path in list(paths):
            try:
                try_publish(path)
                any_success = True
                paths.remove(path)
            except subprocess.CalledProcessError:
                pass

        if not any_success:
            break


if __name__ == '__main__':
    main()
