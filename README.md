# <p align="center"> <b> Anti_Mainland  </b> </p>  

Just like the name,this tools can make chinese botnet never touch your VPS or maybe got bann by Great Firewall of China 😂😂  

this tools based on [honeypot](https://github.com/ppacher/honeyssh) so this tools will stored user&pass in database(sqlite)

#### How this tools work?
well this tools work/implemented on [Layer 8](https://www.computerhope.com/jargon/l/layer8.htm) and this tools just ```print some tcp ASCII banner``` in client 
*see source code*

#### How to use?
you can build it by self or pulling from [docker hub](https://hub.docker.com/r/justhumanz/kick_mainland)  
```
docker pull justhumanz/kick_mainland
docker run -itd --name xianjing -p 22:22 -p 4000:4000 justhumanz/kick_mainland
```
Port 22 for honeypot ssh and port 4000 for API 