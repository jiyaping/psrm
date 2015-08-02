# Author        : jiyaping
# Date          : 2015-7-27
# Description   : server configuration

$global:default_user = "administrator"
$global:default_group = "foc"
$global:servers = @{
    "10.12.30.113"=@{"uname"="shnair";"iislog"="C:\inetpub\logs\LogFiles\W3SVC1"}
    "10.21.7.35"=@{"uname"="jiping";"iislog"="C:\WINDOWS\system32\LogFiles\W3SVC1\"}
    "10.10.65.130"=@{"uname"="oc";"iislog"="C:\inetpub\logs\LogFiles\W3SVC1\"}
}

$global:groups=@{
    "fc"="10.221.7.35,10.120.65.130"
    "oc"="10.12.230.113"
}