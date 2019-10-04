# Signed deliverables and change log

[Version 1.1.09](sas-wvda-1.1.09-windows.zip)
* sas-wvda script can support localized messages, only English present at this time.
* Turn off Windows Search Service.
* Deconfigure Windows Defender Credential Guard.
* Validate Domain Accounts for postgres.
* Ensure all data is passed to Domain Administrator script if the user running this does not have full permissions.
* New message to user if an error is encountered while checking a group membership.

[Version 1.1.08](sas-wvda-1.1.08-windows.zip)
* Validate user is running under domain credentials or exit.

[Version 1.1.07](sas-wvda-1.1.07-windows.zip)
* Moved environment validation earlier in execution flow to avoid issues running in 32-bit windows

[Version 1.1.06](sas-wvda-1.1.06-windows.zip)
* Initial Github release
