# ESOCKS

**Esocks** is a command line applcation which can  creating a **SOCKS5** server easily. It's powered by [Fucksocks](http://github.com/fengyouchao/fucksocks)

# REQUIRE

**Esocks** requres JRE 7+

# DOWNLOAD

You can download **Esocks** at [Release Page](https://github.com/fengyouchao/esocks/releases)

# HOW TO USE
Create a **SOCKS5** server at port 1080 without authentication.

	java -jar esocks.jar
	
See usages:

	java -jar esocks.jar -h

Here are some options:

- --port=[NUMBER]
- --user=[USERNAME:PASSWORD]
- --none_auth=false
- --max-connection=[NUMBER]
- --white-list=IP-IP,IP
- --black-list=IP-IP,IP
- --proxy=[HOST,PORT]
- --ssl=[KEY_STORE,KEY_STORE_PASSWORD,TRUST_KEY_STORE,TRUST_KEY_STORE_PASSWORD]
