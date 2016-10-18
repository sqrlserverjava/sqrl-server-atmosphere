<!--- http://dillinger.io/ --->

# sqrl-server-atmosphere

This java library is a companion to the  [sqrl-server-base](https://https://github.com/dbadia/sqrl-server-base) project.  This library provides auto login to a website using SQRL client, as seen on the demo site: https://sqrljava.tech:20000/sqrlexample/login

#### Integration
Include this library in your distribution, then set `SqrlConfig clientAuthStateUpdaterClass` to `com.github.dbadia.sqrl.atmosphere.AtmosphereClientAuthStateUpdater`