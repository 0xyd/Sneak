# Stealther
Stealther is a spider traveling between dark and light. 
It hides itself in the tor network and no make others feel creepy...

## Dependencies
requests
lxml
stem

## Before U Start develop


Mac:
1. Find out the torrc under the path  ~/Library/Application Support/TorBrowser-Data/Tor/torrc
2. Delete the comment symbol of ControlPort
3. (Option) Change the port number of ControlPort
4. Delete the comment symbol of CookieAuthentication
5. Delete the comment symbol of HashedControlPassword
6. run
```
sudo tor -f torrc
```



