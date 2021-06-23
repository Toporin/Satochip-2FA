# Satochip 2-Factor-Authentication

This is an app to be installed on a second device, to approve transactions before signing them with a Satochip.
The app regularly poll the Electrum server for new transaction proposals. These transaction candidates are then parsed and displayed. If approved, a cryptographic code is sent back to securely and uniquely approve the transaction so that the satochip can sign it.

## Requirements

Kivy does not retrieve the (non-core) python modules imports. These must be added prior to building otherwise the app will crash upon running. 
In this case some error messages will be available via the android logs (something like "ModuleNotFoundError: No module named 'requests'. Python for android ended.").

The following python modules are required:
urllib3
chardet 
requests
certifi 
idna    
cryptos (https://github.com/primal100/pybitcointools)

These modules should be copied into the project's root folder along with the main.py file.

The project also requires the [ethereum-lists/chains](https://github.com/ethereum-lists/chains) repository for supporting EVM-based Chains.

This can be done using the bash file 'make_packages'.

## Build the app

The app is based on the Kivy GUI framework that allows to package a python application into an android app.
Kivy can be installed using the procedure described here: https://kivy.org/doc/stable/installation/installation-linux.html
To package the app in android, you need to install the Buildozer tools as described here: https://kivy.org/doc/stable/guide/packaging-android.html

The app can be built on ubuntu with Kivy-Buildozer with the following commands:

    ```
    $ buildozer android debug
    ```
The resulting apk file is located in the 'bin' folder. It can be installed on an android device (configured for development) with adb:
	
	```
    $ adb install ./bin/Satochip2FA-0.1-debug.apk
    ```
	
For debugging purpose, android logs are available through adb logcat (search for the 'python' keyword):
	
    ```
    $ adb logcat >logs.txt
    ```
	
## permissions

The app requires the CAMERA and STORAGE permissions. If these permissions are not automatically set when installing the application (e.g. via adb), they can be enabled in:
'Settings -> Apps -> Satochip-2FA -> Permissions'