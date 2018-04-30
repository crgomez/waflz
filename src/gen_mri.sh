#!/bin/sh
rm -f _libwaflz.mri
echo "create libwaflz.a" >> _libwaflz.mri
echo "addlib $1/build/ext_yajl-prefix/src/yajl-2.1.1/lib/libyajl_s.a" >> _libwaflz.mri
echo "addlib libwaflzcore.a" >> _libwaflz.mri
echo "save" >> _libwaflz.mri
echo "end" >> _libwaflz.mri
