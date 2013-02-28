# VIM Crypto in Node.js

## Goal

To be able to implement a system where certain sensitive files would be encrypted by vim, then read by node using a system/environment key (hence putting some level of protection on those files). Think configuration files.

## Info

* vim7.3
* blowfish
* crypted file is file
* password is test
* The Perl script comes from [Yuri Volkov](http://yuri-volkov.com/?page_id=9), with small modification. This is the inspiration for this effort.

## So far

* Required data is properly extracted
* Key is generated properly
* Decryption still doesn't work.

If anyone has solution(s) to offer, please fork an pull-request.
