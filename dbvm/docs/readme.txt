Write vmdisk.img to a floppy disk or burn vmcd.iso to cd and boot off it. 
When it's done loading remove the disk and your system will boot further

To make use of vmcall you must provide valid credentials. DBVM no longer ships
with public default passwords. Passwords are generated/obfuscated at runtime
and can be changed via the VMCALL_CHANGEPASSWORD command. Refer to vmcall.txt
for the structure layout and update your calling code accordingly.

System requirements:
Intel Core2Duo and higher, or a Intel DualCore 9x0. Other variants won't work
At least 16MB ram

If you have a AMD and want a version for those systems, then please donate $2000 to dark_byte@hotmail.com with paypal

Name suggestions for this tool are appreciated.
