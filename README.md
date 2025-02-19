<h1>check it (WIP)</h1>

## Desc
<p>"Check it" is supposed to be tool for checking which exploit mitigations are enabled in a binary. Currently its WIP.</p>

## Todo
1. add support for elf 32 bit...

## Compiling
```
git clone https://github.com/ch4insmoker/checkit
cd checkit
mkdir build
cd build
cmake ..
cmake --build .
```

## Reference
<a href="https://man7.org/linux/man-pages/man5/elf.5.html">elf man page</a>
<br>
<a href="https://stevens.netmeister.org/631/elf.html">some elf blog</a>
<br>
<a href="https://lwn.net/Articles/631631/">lwn elf blog</a>
<br>
<a href="https://intezer.com/blog/research/executable-linkable-format-101-part1-sections-segments/">elf 101 </a>
<br>
<a href="https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/elf/elf.py">pwntools checksec src </a>
<br>
<a href="https://github.com/can1357/linux-pe">linux-pe</a>
