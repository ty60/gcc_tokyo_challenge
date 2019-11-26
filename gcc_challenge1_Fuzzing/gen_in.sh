#!/bin/bash

if [ ! -d ./in_dir ]; then
    mkdir in_dir
fi

python3 -c "import sys; sys.stdout.buffer.write(b'A')" > in_dir/short
python3 -c "import sys; sys.stdout.buffer.write(b'B'*200)" > in_dir/long
