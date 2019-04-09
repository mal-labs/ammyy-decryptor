# ammyy-decryptor
ammyy-decryptor is a python script that can be utilized for decrypting FlawedAmmyy executables. This script will attempt to retrieve the key from the specified unpacked downloader and utilize the key to decrypt the FlawedAmmyy sample. The decrypted sample will be written to <b>decrypted.txt</b>.The following samples were utilized during the creation and testing of this script:
- Packed downloader (MD5: 28eae907ea38b050cbdcc82bb623c00a)
- Unpacked downloader (MD5: d920413442adde78394077c2bde093d8)
- Encrypted FlawedAmmyy (MD5: 651df83a583b0eefd0e3d39c4f020f11)

# Prerequisites
The following python libraries are utilized by ammyy-decryptor:
- binascii
- os
- re
- shutil
- argparse

ammyy-decryptor also requires the following:
- Unpacked FlawedAmmyy downloader OR key utilized for decryption
- Encrypted FlawedAmmyy executable

# Output
$ python2 ammyy-decryptor.py -l loader.txt -a ammyy.txt 
```
Potential keys discovered:
['qfewjq4ewqf32df43dFD2h5', 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD']
Attempting decryption with key: qfewjq4ewqf32df43dFD2h5
Decryption Successful!
```
