# fasthttps

development Login -> Photos -> Photos2 -> Token -> MapV3

## fastHttpsWSNV12

This program derives from fastHttpWSNV12.
" /domain=domstr /port=portstr [/index=idxfil] [/preload] [/dbg]"
Key features:
 - websocket upgrader
 - depends on outdated dir "/home/peter/www/azuldist/" as base for index files
 - has a preloader. The preloader is a feature that parses the index file for references to other javascript files. 
   If tagged, the preloader incorporates the content of the referenced js files into the index file.  
   This feature is now superceded with an exoplict embed program.  
 - The default handler uses a switch program as a router to direct to specific handlers.  

## fastHttpsSni.go

This program

 - uses map
 - uses tls config to check the server name

```
    tlsconfig := &tls.Config{
        Certificates: CertList,
//      GetCertificate:
        GetConfigForClient: GetConfigForClientHandler,
    }

    ln, err := tls.Listen("tcp", ":"+portStr , tlsconfig)
    if err != nil {log.Fatalf("error -- creating listener: %v\n", err)}
    defer ln.Close()

//  serverMain := &fasthttp.Server {Handler: han.requestHandler}
//  serverAdmin := &fasthttp.Server {Handler: han.reqHandlerAdmin}

    err = fasthttp.Serve(ln, han.requestHandler);
    if err != nil {log.Fatalf("error in Serve: %v\n", err)}
```

todo:



## fastHttpsMapV3

uses new base folder for index files:  "/home/peter/cloud/domains/"

uses map


## fastHttpsPhotos2

demo program to read photos from google.
since gphotos does not allow access anymore, this program is deprecated.

## fastHttpsLogin

" /domain=domstr /port=portstr [/index=idxfil] [/preload] [/dbg]"
This program uses google login to verify the user. 
 - uses map as router

## fastHttpsToken

 " /domain = domstr /port=portstr [/index=idxfil] /auth=yamlfil [/dbg]"

