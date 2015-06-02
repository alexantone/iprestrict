# iprestrict
Automatically exported from code.google.com/p/iprestrict

iprestrict

This application is intended to block any inbound traffic on an interface if it matches certain rules.

Rule types:

    single ip in dotted decimal format;
    subnet in netaddress/mask format where mask is less than 32;
    range specifed as doted decimal startip-stopip where startip < stopip;
    all which denotes any ip; 

Rule syntax:

    {allow | deny} {ip <ipaddr> | subnet <net>/<mask> | range <ip1>-<ip2> | all} 

Comments start with a #(pound) sign.

By default, if no rule is matched then "deny all" is applied. If a permisive behaviour is wanted then all you have to do is to put "allow all" at the end of the configuration file.

The blocking is done based on source ip address by colliding on a subinterface, so the program learns and sets the subinterfaces after seeing a packet with a matchind ip. Administrative permision is required to run the program.

Usage:

    iprestrict [-i <interface>] [-f <configuration file>] iprestrict --help 

Option 	Description
-i <interface> 	specify the interface to be monitored. If missing, the default interface is used.
-f <configuration file>	specify the configuration file. If missing the program will look for iprestrict.cfg in /etc/ or the current dir.
--help	show this usage message.
