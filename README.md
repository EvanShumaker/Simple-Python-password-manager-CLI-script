# Simple-Python-password-manager-CLI-script
This script serves as a simple, bare bones password manager I made as a learning experience. It has functions for initialization, adding passwords, deleting them, fetching them, and listing them. It prompts the user to create a master password that will be used to access any other passwords stored with the script. 
The master password isn’t stored anywhere. Instead, the program combines it with a random salt and uses PBKDF2-HMAC-SHA256 to create a secure key. That key encrypts and decrypts your saved passwords using Fernet (AES encryption with built in integrity checks). The result is an encrypted JSON file that only your master password can unlock.


## Features
- Initialize a master-password protected vault (`init`)
- Add entries with username, password, and notes (`add`)
- Retrieve an entry (`get`)
- List all entry names (`list`)
- Remove an entry (`rm`)
- Secure encryption using `cryptography` (Fernet) with a PBKDF2-derived key

## Heres how to use the script:
## initialize vault (run once)
python password_manager.py init

## add an entry
python password_manager.py add <name/key>

## get an entry
python password_manager.py get <name/key>

## list entries
python password_manager.py list

## remove an entry
python password_manager.py rm <name/key>
