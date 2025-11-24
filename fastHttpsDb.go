
// fastHttpsDb 
// from fastHttpsMapV5
//
// building a webserver based on wasgob and fasthttp tls
//
// Author: prr, azul software
// Date 13 July 2024
// copyright (c) 2024 prr, azul software
//
// embeds script files
//
// binary transport
//
// map: replace switch with a map of funcs
//

package main

import (
	"os"
	"log"
	"fmt"
	"bytes"
	"strings"
	"net"
	"io"
//	"io/ioutil"
	"unsafe"
	"context"
	"time"
	"strconv"

	"github.com/prr123/fasthttpServer/fasthttp/upgrader"
	"github.com/prr123/fasthttpServer/fasthttp/pathparser"

	"github.com/gobwas/ws"
	"github.com/valyala/fasthttp"
	"github.com/goccy/go-json"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"

    util "github.com/prr123/utility/utilLib"
)

type address struct {
	Street string
	StNum string
	AptNum string
	City string
	Zip string
	Country string
}

type persProp struct {
	Id int `db:"Id"`
	First string `db:"first"`
	Middle string `db:"middle"`
	Last string `db:"last"`
	Email string `db:"email"`
	Phone string `db:"phone"`
	Cre	time.Time `db:"created"`
	Edit time.Time `db:"edited"`
}

type noteProp struct {
	Id int `db:"Id"`
	Pid int `db:"pid"`
	Txt string `db:"txt"`
	Cre	time.Time `db:"created"`
	Edit time.Time `db:"edited"`
}

type Rtyp struct {
    fil *os.File
    ftyp string
    }

type Handler struct {
	dbg bool
	test bool
    router map[string] Rtyp
	p pparse.Path
	index *[]byte
	idxLen int
	oaState string
	wwwBase string
	dbPool *pgxpool.Pool
}

type scrIns struct {
	filnam string
	st int
	end int
	src int
}

type jsNote struct {
	Id int `json:"id"`
	Txt string `json:"txt"`
}

var hmap = make(map[string]func(h Handler, ctx *fasthttp.RequestCtx))

func main() {

	ctx := context.Background()
    numarg := len(os.Args)
    flags:=[]string{"dbg", "domain", "port", "index"}

    useStr := " /domain=domstr /port=portstr [/index=idxfil] [/dbg]"
    helpStr := "fasthttps server"

    if numarg > len(flags) +1 {
        fmt.Println("too many arguments in cl!")
        fmt.Println("usage: %s %s\n", os.Args[0], useStr)
        os.Exit(-1)
    }

    if numarg == 1 || (numarg > 1 && os.Args[1] == "help") {
        fmt.Printf("help: %s %s\n", os.Args[0], helpStr)
        fmt.Printf("usage is: %s %s\n", os.Args[0], useStr)
        os.Exit(1)
    }

    flagMap, err := util.ParseFlags(os.Args, flags)
    if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

	dbg:= false
    _, ok := flagMap["dbg"]
    if ok {dbg = true}

	test:= false
    _, ok = flagMap["test"]
    if ok {test = true}

    domStr := ""
    domval, ok := flagMap["domain"]
    if !ok {
        log.Fatalf(" error -- no domain flag!\n")
    } else {
        if domval.(string) == "none" {log.Fatalf("error: no domain provided!\n")}
        domStr = domval.(string)
    }

    portStr := ""
    pval, ok := flagMap["port"]
    if !ok {
        log.Fatalf(" error port flag!\n")
    } else {
        if pval.(string) == "none" {log.Fatalf("error: no port provided!\n")}
        portStr = pval.(string)
    }

    rootFil := "index"
    rval, ok := flagMap["index"]
    if ok {
        if rval.(string) == "none" {log.Fatalf("error: no index file name provided!\n")}
        rootFil = rval.(string)
    }

	han := Handler{
		dbg: dbg,
		test: test,
	}

	// check domain
	certDir := "/home/peter/cloud/domains/" + domStr + "/devops/"
	 _, err = os.Stat(certDir)
    if os.IsNotExist(err) {
        log.Fatalf("error -- domain directory %s does not exist\n", domStr)
    } else if err != nil {
        log.Fatalf("error -- checking directory: %v\n", err)
    }

	certNam := []byte(domStr)
	for i:=0; i< len(domStr); i++ {if certNam[i] == '.' {certNam[i]='_'}}
	cert := certDir + string(certNam) + ".crt"
	_, err = os.Stat(cert)
	if err != nil {log.Fatalf("error -- cert file: %v\n", cert)}
	key := certDir + string(certNam) + ".key"
	_, err = os.Stat(key)
	if err != nil {log.Fatalf("error -- key file: %v\n", cert)}

	han.wwwBase = "/home/peter/cloud/domains/" + domStr
	if dbg {
		fmt.Println("*********** debug info *****************")
		fmt.Printf("found tls files!\n")
		fmt.Printf("domain: %s\n", domStr)
		fmt.Printf("wwwBase: %s\n", han.wwwBase)
		fmt.Printf("public cert: %s\n", cert)
		fmt.Printf("priv cert: %s\n", key)
		fmt.Println("********* end debug info ***************")
	}
    han.router = make(map[string]Rtyp)

    idxFilnam := han.wwwBase + "/html/" + rootFil + ".html"
	idxfil, err := os.Open(idxFilnam)
    if err != nil {log.Fatalf("error -- cannot open index file: %v\n", err)}
    idx := Rtyp {
        fil: idxfil,
        ftyp: "text/html",
    }
    han.router["index.html"] = idx

	//create db connection
    connStr := "postgres://azuladmin@/azuldb?host=/var/run/postgresql/"
	han.dbPool, err = pgxpool.New(ctx, connStr)
    if err != nil {log.Fatalf("error -- Unable to create pool connection: %v\n", err)}
    defer han.dbPool.Close()
//	han.dbPool = dbpool

	idxlen := 1024*100
	idxbyt := make([]byte, idxlen)
	n, err:= idxfil.Read(idxbyt)
	if err != nil {log.Fatalf("error -- reading idx file: %v\n",err)}
	if n == idxlen {log.Fatalf("error -- idxlen too small!\n")}

	if dbg {fmt.Printf("dbg -- idx [%d]: %s\n%s\n", n, idxFilnam, string(idxbyt))}
	han.index = &idxbyt
	idxlen = n
	han.idxLen = n


	hmap["/"] = (Handler).idxHandler
	hmap["/html/"]	= (Handler).htmlHandler
	hmap["/js/"]	= (Handler).jsHandler
	hmap["/js/md/"]	= (Handler).jsHandler
	hmap["/js/frag/"]	= (Handler).jsHandler
	hmap["/pdf/"]	= (Handler).pdfHandler
	hmap["/hijack"]	= (Handler).wsHandler
	hmap["/xjs/"]	= (Handler).xjsonHandler
	hmap["/db/"]	= (Handler).dbHandler

//	hmap["/login"]	= (Handler).loginHandler

	log.Printf("info -- starting to listen at %s at port: %s\n", domStr, portStr)
	err = fasthttp.ListenAndServeTLS(":"+portStr, cert, key, han.requestHandler)
	if err != nil {log.Printf("error Listen: %v\n", err)}
}

	// the corresponding fasthttp request handler
func (han Handler)requestHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg request: %q method: %q path: %q\n", ctx.RequestURI(), ctx.Method(), ctx.Path())}

	// find etension and folder path -> parse ctx.PATH

	p := pparse.Pparse(ctx.Path())

	fn, ok := hmap[string(p.Fold)]
	if !ok {
		if len(p.Fnam) == 0  && len(p.Ext) == 0 {
			p.Fnam = append(p.Fnam, p.Fold[1:] ...)
			p.Fnam = append(p.Fnam, []byte(".html") ...)
			p.Ext =  []byte("html")
			p.Fold = []byte("/html/")
			han.p = p
			han.htmlHandler(ctx)
			return
		} else {
			if han.dbg {log.Println("unsupported path!")}
			ctx.Error("Unsupported path", fasthttp.StatusNotFound)
			return
		}
	}
	if han.dbg {log.Printf("dbg Fold: %s Fnam: %s Ext: %s\n", p.Fold, p.Fnam, p.Ext)}

	han.p = p
	fn(han, ctx)
}

	// request handler in fasthttp style, i.e. just plain function.
func (han Handler)fooHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hi there! foo here! RequestURI is %q! dbg: %t body:\n", ctx.RequestURI(), han.dbg)
	fmt.Fprintf(ctx, "Hello, world!\n\n")

	fmt.Fprintf(ctx, "Request method is %q\n", ctx.Method())
	fmt.Fprintf(ctx, "RequestURI is %q\n", ctx.RequestURI())
	fmt.Fprintf(ctx, "Requested path is %q\n", ctx.Path())
	fmt.Fprintf(ctx, "Host is %q\n", ctx.Host())
	fmt.Fprintf(ctx, "Query string is %q\n", ctx.QueryArgs())
	fmt.Fprintf(ctx, "User-Agent is %q\n", ctx.UserAgent())
	fmt.Fprintf(ctx, "Connection has been established at %s\n", ctx.ConnTime())
	fmt.Fprintf(ctx, "Request has been started at %s\n", ctx.Time())
	fmt.Fprintf(ctx, "Serial request number for the current connection is %d\n", ctx.ConnRequestNum())
//	fmt.Fprintf(ctx, "Your source adr is %q\n", ctx.RemoteAddr.String())
	con:= ctx.Conn()
	adr := con.RemoteAddr()
	fmt.Fprintf(ctx, "remote addr: %q \n", adr.String())
	idx := strings.Index(adr.String(), ":")
	port := adr.String()[idx+1:]
	fmt.Fprintf(ctx, "port: %s\n", port)
	// unique id
	fmt.Fprintf(ctx,"connection seq: %d\n",  ctx.ConnRequestNum())
	if ctx.ConnRequestNum() == 1 {fmt.Fprintf(ctx,"need to login!\n")}

	fmt.Fprintf(ctx,"connection id: %d\n\n", ctx.ConnID())

	authVal:= ctx.Request.Header.Peek("Authorization")
	fmt.Fprintf(ctx,"auth value: %s\n", authVal)

	numHeaders := ctx.Request.Header.Len()
	head := ctx.Request.Header.RawHeaders()
	fmt.Fprintf(ctx, "headers [%d]:\n%s\n", numHeaders, head)
	fmt.Fprintf(ctx, "end headers\n")
	fmt.Fprintf(ctx, "\nRaw request is:\n---START---\n%s\n---END---", &ctx.Request)

	ctx.SetContentType("text/plain; charset=utf8")

/*
	// Set arbitrary headers
	ctx.Response.Header.Set("X-My-Header", "my-header-value")

	// Set cookies
	var c fasthttp.Cookie
	c.SetKey("cookie-name")
	c.SetValue("cookie-value")
*/

}


func (han Handler)idxHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg -- index %s %s %s\n", han.p.Fold, han.p.Fnam, han.p.Ext)}

    ctx.SetContentType("text/html; charset=utf-8")
	out := *han.index
//	if han.test {fmt.Printf("dbg -- out\n%s\n",string(out[:han.idxLen]))}
	n, err := ctx.Write(out[:han.idxLen])
	if err != nil {log.Fatalf("error -- ctx write: %v", err)}
    if han.dbg {fmt.Printf("dbg index -- sent: %d\n", n)}

}


func (han Handler)htmlHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg -- index %s %s %s\n", han.p.Fold, han.p.Fnam, han.p.Ext)}

	if !bytes.Equal(han.p.Ext, []byte("html"))  {
        log.Printf("error htmlHandler -- invalid req: %s\n", ctx.Path)
        ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "invalid req: %s\n",ctx.Path)
        return
	}

    ctx.SetContentType("text/html; charset=utf-8")

	filnam := han.wwwBase + "/html/" + string(han.p.Fnam)
	if han.dbg {log.Printf("dbg -- info htmlHandler -- filnam: %s\n",filnam)}

	fil, err := os.Open(filnam)
	if err != nil {
		log.Printf("error -- htmlHandler -- ctx open: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n", filnam)
		return
	}

    fil.Seek(0,0)
    n, err := io.Copy(ctx, fil)
	if err != nil {
		log.Printf("error -- jsHandler -- ctx copy: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}

	if han.dbg {log.Printf("dbg info -- jsHandler -- sent %d \n", n)}
//	n, err := ctx.Write(out[:han.idxLen])
//	if err != nil {log.Fatalf("error jsHandler -- ctx write: %v", err)}

}

func (han Handler)jsHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg -- index %s %s %s\n", han.p.Fold, han.p.Fnam, han.p.Ext)}

	if !bytes.Equal(han.p.Ext, []byte("js"))  {
        log.Printf("error jsHandler -- invalid req: %s\n", ctx.Path)
        ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "invalid req: %s\n",ctx.Path)
        return
	}

    ctx.SetContentType("application/javascript; charset=utf-8")

	filnam := han.wwwBase + string(ctx.Path())
	if han.dbg {log.Printf("dbg -- info jsHandler -- filnam: %s\n",filnam)}

	fil, err := os.Open(filnam)
	if err != nil {
		log.Printf("error -- jsHandler -- ctx open: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}

    fil.Seek(0,0)
    n, err := io.Copy(ctx, fil)
	if err != nil {
		log.Printf("error -- jsHandler -- ctx copy: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}

	if han.dbg {log.Printf("dbg info -- jsHandler -- sent %d \n", n)}
}

func (han Handler)imgHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg imgHandler -- method: %q index %s %s %s\n", ctx.Method(), han.p.Fold, han.p.Fnam, han.p.Ext)}


	switch string(han.p.Ext) {
	case "png": 
    	ctx.SetContentType("image/png")
	case "jpg", "jpeg":
    	ctx.SetContentType("image/jpeg")
	case "gif":
    	ctx.SetContentType("image/gif")

	default:
        log.Printf("error imgHandler -- invalid type: %s\n", han.p.Ext)

        ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "invalid req: %s\n",ctx.Path)
        return
	}

	filnam := han.wwwBase + string(ctx.Path())
	if han.dbg {log.Printf("dbg info imgHandler -- filnam: %s\n",filnam)}

	fil, err := os.Open(filnam)
	if err != nil {
		log.Printf("error imgHandler -- open file: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}
	info, err := fil.Stat()
	if err != nil {
		log.Printf("error imgHandler -- file Stat: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not get size of file: %s\n",ctx.Path)
		return
	}

	ctx.Response.Header.SetContentLength(int(info.Size()))
    fil.Seek(0,0)
    n, err := io.Copy(ctx, fil)
	if err != nil {
		log.Printf("error imgHandler -- ctx copy: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not copy file: %s\n",ctx.Path)
		return
	}

	if han.dbg {log.Printf("dbg info imgHandler -- sent %d \n", n)}
	return
}

func (han Handler)jsonHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg jsonHandler -- method: %q index %s %s %s\n", ctx.Method(), han.p.Fold, han.p.Fnam, han.p.Ext)}

	if !bytes.Equal(han.p.Ext, []byte("json"))  {
        fmt.Printf("error jsonHandler -- invalid req: %s\n", ctx.Path)
        ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "invalid req: %s\n",ctx.Path)
        return
	}

    ctx.SetContentType("application/json; charset=utf-8")

	filnam := han.wwwBase + string(ctx.Path())
	if han.dbg {fmt.Printf("info jsonHandler -- filnam: %s\n",filnam)}

	fil, err := os.Open(filnam)
	if err != nil {
		log.Printf("error jsonHandler -- open file: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}
    fil.Seek(0,0)
    n, err := io.Copy(ctx, fil)
	if err != nil {
		log.Printf("error jsonHandler -- ctx copy: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}

	if han.dbg {log.Printf("info jsonHandler -- sent %d \n", n)}

}

func (han Handler)xjsonHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg xjson -- method: %q index %s %s %s\n", ctx.Method(), han.p.Fold, han.p.Fnam, han.p.Ext)}

	if !bytes.Equal(ctx.Method(), []byte("POST")) {
		log.Printf("error xjsonHandler -- method %s not post!\n", ctx.Method())
		return
	}

	res := ctx.PostBody()
	if han.dbg {log.Printf("dbg xjson -- rec: %s\n",string(res))}

	var jsonMap map[string]string
	err := json.Unmarshal(res, &jsonMap)
	if err != nil {
		log.Printf("error -- jsonMap: %v\n", err)
	}
	for k,v := range jsonMap {
		fmt.Printf("k: %s v: %s\n",k,v)
	}

	switch string(han.p.Fnam) {

	default:
		log.Printf("dbg -- %s\n", han.p.Fnam)
	}

/*
 	err := json.Unmarshal(res, &adL)
	if err != nil {
		log.Printf("error xjsonHandler -- conversion: %v!\n", err)
		return
	}
	PrintADL(adL)
*/
	ctx.SetStatusCode(200)

}

func (han Handler)dbHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg db -- method: %q index %s %s %s\n", ctx.Method(), han.p.Fold, han.p.Fnam, han.p.Ext)}

	if !bytes.Equal(ctx.Method(), []byte("POST")) {
		log.Printf("error -- dbHandler -- method %s not post!\n", ctx.Method())
		return
	}

	res := ctx.PostBody()
	if han.dbg {log.Printf("dbg db json -- rec: %s\n",string(res))}

	var jsonMap map[string]string
//	var notesMap []jsNote

	err := json.Unmarshal(res, &jsonMap)
	if err != nil {
		log.Printf("error -- db jsonMap: %v\n", err)
	}

	if han.dbg {
		for k,v := range jsonMap {
			fmt.Printf("k: %s v: %s\n",k,v)
		}
	}

	cmdStr, ok := jsonMap["cmd"]
	if ok {
		fmt.Printf("info -- cmd: %s\n", cmdStr)
	} else {
		log.Printf("error -- no db cmd\n")
		return
	}

	dbpool := han.dbPool
	var (
		strContentType = []byte("Content-Type")
		strApplicationJSON = []byte("application/json")
	)
	switch cmdStr {
	case "add":
	    query := "insert into person (first, last, email) values ($1, $2, $3);"
	    tag, err := dbpool.Exec(ctx, query, jsonMap["First"], jsonMap["Last"], jsonMap["Email"])
		if err != nil {log.Fatalf("error -- insert failed: %v\n", err)}
    	fmt.Printf("tag: %s\n", tag.String())
		ctx.SetStatusCode(200)
		return

	case "list":
		liQuery := "select * from person;"
		rows, err := dbpool.Query(ctx, liQuery)
		if err != nil {log.Fatalf("error -- query failed: %v\n", err)}
    	defer rows.Close()

    	personList, err := pgx.CollectRows(rows, pgx.RowToStructByPos[persProp])
    	if err != nil {log.Fatalf("error -- CollectRows failed: %v\n", err)}
		fmt.Printf("Person List: %d\n", len(personList))

		//create json and send person list as a  json to client
		outB, err := json.Marshal(personList)
    	if err != nil {log.Fatalf("error -- json Marshal: %v\n", err)}
		fmt.Printf("Person List json: %s\n", outB)

		ctx.Response.Header.SetCanonical(strContentType, strApplicationJSON)
		ctx.Response.SetStatusCode(200)
		_, err = ctx.Write(outB)
		if err != nil {log.Fatalf("error -- dbHandler ctx write resp: %v", err)}
		return
/*
    	fmt.Println("******* tables ******")
    	for _, tp := range tableList {
        	fmt.Printf("%s %s %s\n",tp.Schemaname, tp.Tablename, tp.Tableowner)
    	}
    	fmt.Println("***** end tables ****")
*/

	case "upd":
		if han.dbg {fmt.Printf("dbg -- update\n")}

		key := make([]string,0,10)
		val := make([]string,0,10)
		id := 0
		wStr := ""
		count := 0

		for k, v := range jsonMap {
			if k == "cmd" {continue}
			if k == "Id" {
				id, err = strconv.Atoi(v)
				if err != nil {
					log.Printf("error -- upd id conv: %v",err)
					continue
				}
				if han.dbg {fmt.Printf("dbg -- Id: %d\n", id)}
				continue
			}
			count++
			key = append(key, k)
			val = append(val, v)
			qStr := fmt.Sprintf("%s='%s',",k, v)
			wStr = wStr + qStr
		}
		wStr = strings.TrimSuffix(wStr, ",")
		if han.dbg {fmt.Printf("dbg --- aux query: %s\n",wStr)}

		query:= fmt.Sprintf("update person set %s where Id = $1;", wStr)
	    tag, err := dbpool.Exec(ctx, query, id)
		if err != nil {log.Fatalf("error -- insert failed: %v\n", err)}
    	fmt.Printf("tag: %s\n", tag.String())
		ctx.SetStatusCode(200)

		if han.dbg {fmt.Printf("dbg -- success upd\n")}
		return

	case "se":
		if han.dbg {fmt.Printf("dbg -- search\n")}

		key := make([]string,0,10)
		val := make([]string,0,10)
		id := 0
		wStr := ""
		count := 0
		for k, v := range jsonMap {
			if k == "cmd" {continue}
			if k == "Id" {
				id, err = strconv.Atoi(v)
				if err != nil {
					log.Printf("error -- upd id conv: %v",err)
					continue
				}
				if han.dbg {fmt.Printf("dbg -- Id: %d\n", id)}
			}
			count++
			key = append(key, k)
			val = append(val, v)
			qStr := fmt.Sprintf("%s like '%s' and ",k, v)
			wStr = wStr + qStr
		}

		wStr = strings.TrimSuffix(wStr, " and ")
		wStr += ";"
		if han.dbg {fmt.Printf("dbg --- aux query: %s\n",wStr)}

		liQuery := "select * from person where " + wStr
		if han.dbg {fmt.Printf("dbg -- query:\n%s\n",liQuery)}

		rows, err := dbpool.Query(ctx, liQuery)
		if err != nil {log.Fatalf("error -- query failed: %v\n", err)}
    	defer rows.Close()

    	personList, err := pgx.CollectRows(rows, pgx.RowToStructByPos[persProp])
    	if err != nil {log.Fatalf("error -- CollectRows failed: %v\n", err)}
		fmt.Printf("Person List: %d\n", len(personList))

		//create json and send person list as a  json to client
		outB, err := json.Marshal(personList)
    	if err != nil {log.Fatalf("error -- json Marshal: %v\n", err)}
		fmt.Printf("Person List json: %s\n", outB)

		ctx.Response.Header.SetCanonical(strContentType, strApplicationJSON)
		ctx.Response.SetStatusCode(200)
		_, err = ctx.Write(outB)
		if err != nil {log.Fatalf("error -- dbHandler ctx write resp: %v", err)}
		return

	// list Notes
	case "liN":
		if han.dbg {fmt.Printf("dbg -- list Notes\n")}

		IdStr, ok := jsonMap["pid"]
		if !ok {
			log.Printf("error -- no pid!\n")
			ctx.SetStatusCode(405)
			return
		}
		id, err := strconv.Atoi(IdStr)
		if err != nil {
			log.Printf("error -- pid not int: %v",err)
			return
		}
		if han.dbg {fmt.Printf("dbg -- Id: %d\n", id)}

		liQuery := "select * from notes where pid=$1 order by id desc;"
		rows, err := dbpool.Query(ctx, liQuery, id)
		if err != nil {
			ctx.Response.SetStatusCode(405)
			log.Fatalf("error -- query failed: %v\n", err)}
    	defer rows.Close()

    	noteList, err := pgx.CollectRows(rows, pgx.RowToStructByPos[noteProp])
    	if err != nil {log.Fatalf("error -- CollectRows failed: %v\n", err)}
		fmt.Printf("Note List: %d\n", len(noteList))

		//create json and send person list as a  json to client
		outB, err := json.Marshal(noteList)
    	if err != nil {log.Fatalf("error -- json Marshal: %v\n", err)}
		fmt.Printf("Note List json: %s\n", outB)

		ctx.Response.Header.SetCanonical(strContentType, strApplicationJSON)
		ctx.Response.SetStatusCode(200)
		_, err = ctx.Write(outB)
		if err != nil {log.Fatalf("error -- dbHandler ctx write note resp: %v", err)}
		return

	case "addN":
		if han.dbg {fmt.Printf("dbg -- add Note\n")}

		IdStr, ok := jsonMap["pid"]
		if !ok {
			log.Printf("error -- no person id!\n")
			ctx.SetStatusCode(405)
			return
		}
		id, err := strconv.Atoi(IdStr)
		if err != nil {
			log.Printf("error -- pid not int: %v",err)
			return
		}
		if han.dbg {fmt.Printf("dbg -- Id: %d\n", id)}

		txtStr, ok := jsonMap["txt"]
		if !ok {
			log.Printf("error -- no note txt!\n")
			ctx.SetStatusCode(405)
			return
		}
	    query := "insert into notes (pid, txt, created) values ($1, $2, $3);"
	    tag, err := dbpool.Exec(ctx, query, id, txtStr, time.Now())
		if err != nil {log.Fatalf("error -- insert failed: %v\n", err)}
    	fmt.Printf("tag: %s\n", tag.String())
		ctx.SetStatusCode(200)
		return

	case "updN":
		if han.dbg {fmt.Printf("dbg -- upd Note\n")}

		PidStr, ok := jsonMap["pid"]
		if !ok {
			log.Printf("error -- no person id!\n")
			ctx.SetStatusCode(405)
			return
		}

		pid, err := strconv.Atoi(PidStr)
		if err != nil {
			log.Printf("error -- note pid not int: %v",err)
			return
		}
		if han.dbg {fmt.Printf("dbg -- pid: %d\n", pid)}

		noteStr, ok := jsonMap["notes"]
		if !ok {
			log.Printf("error -- no notes!\n")
			ctx.SetStatusCode(405)
			return
		}
		if han.dbg {fmt.Printf("dbg -- notes: %s\n", noteStr)}

		var notesList []jsNote

		err = json.Unmarshal([]byte(noteStr), &notesList)
		if err != nil {
			log.Printf("error -- db notesList: %v\n", err)
		}

		if han.dbg {
			fmt.Printf("dbg --  noteList: %d\n", len(notesList))
			for i:=0; i<len(notesList); i++ {
				fmt.Printf("%d: id: %d -- %s\n", i, notesList[i].Id, notesList[i].Txt)
			}
		}

		for i:=0; i<len(notesList); i++ {
			txtStr := notesList[i].Txt
			id := notesList[i].Id
			query:= fmt.Sprintf("update notes set txt='%s' where id = $1 and pid = $2;", txtStr)
			if han.dbg {fmt.Printf("dbg -- query [id: %d, pid: %d] %s\n", id, pid, query)}
	    	tag, err := dbpool.Exec(ctx, query, id, pid)
			if err != nil {log.Fatalf("error -- update failed: %v\n", err)}
	   	 	fmt.Printf("tag: %s\n", tag.String())
		}

		ctx.SetStatusCode(200)

	default:
		ctx.SetStatusCode(405)
	}
}

func PrintADL (adl []address) {

	fmt.Printf("******** address records: %d *********\n",len(adl))
	for i:=0; i< len(adl); i++ {
		fmt.Printf("Street:  %s\n",adl[i].Street)
		fmt.Printf("Number:  %s\n",adl[i].StNum)
		fmt.Printf("Apt:     %s\n",adl[i].AptNum)
		fmt.Printf("City:    %s\n",adl[i].City)
		fmt.Printf("Zip:     %s\n",adl[i].Zip)
		fmt.Printf("Country: %s\n",adl[i].Country)

	}
	fmt.Printf("******** end address records *********\n")
}

func (han Handler)pdfHandler(ctx *fasthttp.RequestCtx) {

	if han.dbg {log.Printf("dbg index %s %s %s\n", han.p.Fold, han.p.Fnam, han.p.Ext)}

	if !bytes.Equal(han.p.Ext, []byte("pdf"))  {
        fmt.Printf("error pdfHandler -- invalid req: %s\n", ctx.Path)
        ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "invalid req: %s\n",ctx.Path)
        return
	}

    ctx.SetContentType("application/pdf; charset=utf-8")

	filnam := han.wwwBase + string(ctx.Path())
	if han.dbg {fmt.Printf("info pdfHandler -- filnam: %s\n",filnam)}

	fil, err := os.Open(filnam)
	if err != nil {
		log.Printf("error pdfHandler -- open file: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}
    fil.Seek(0,0)
    n, err := io.Copy(ctx, fil)
	if err != nil {
		log.Printf("error pdfHandler -- ctx copy: %v", err)
	    ctx.SetStatusCode(404)
        ctx.SetContentType("text/plain; charset=utf-8")
        fmt.Fprintf(ctx, "could not read file: %s\n",ctx.Path)
		return
	}

	if han.dbg {log.Printf("info pdfHandler -- sent %d \n", n)}
}


func (han Handler)barHandler(ctx *fasthttp.RequestCtx) {
//	fmt.Fprintf(ctx, "Hi there! bar here! RequestURI is %q", ctx.RequestURI())
//	resp:= fasthttp.AcquireResponse()
	ctx.SetStatusCode(401)
    ctx.SetContentType("text/plain; charset=utf8")
	ctx.Response.Header.Set("Authorisation", "abcdefg")
//	ctx.Response.
	ctx.SetBodyString("hello -- this is a test string!\n")
}

/* 
// web socket upgrade
GET /chat HTTP/1.1
Host: example.com:8000
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
*/

func (han Handler)wsHandler(ctx *fasthttp.RequestCtx) {


	if han.dbg {
		log.Printf("ws upgrade!\n")
		upgVal:= ctx.Request.Header.Peek("Upgrade")
		fmt.Printf("upgrade value: %s\n", upgVal)
		conVal:= ctx.Request.Header.Peek("Connection")
		fmt.Printf("connection value: %s\n", conVal)
		wsKeyVal:= ctx.Request.Header.Peek("Sec-WebSocket-Key")
		fmt.Printf("ws Key value: %s\n", wsKeyVal)
		wsVerVal:= ctx.Request.Header.Peek("Sec-WebSocket-Version")
		fmt.Printf("ws version: %s\n", wsVerVal)
	}

	// Upgrade(ctx *fasthttp.RequestCtx, dbg bool)(err error)
	err := upgrader.Upgrade(ctx, han.dbg)
	if err != nil {
		log.Printf("error -- upgrade error: %v\n", err)
		return
	}
	// return hhtp response
	// ctx.Response.Header.Set(key, value)
	// this will get the raw net.Conn

	if han.dbg {log.Printf("upgrade success; hijacking conn\n")}

	ctx.Hijack(hijackHandler)
	fmt.Fprintf(ctx, "Hijacked the connection!")
}


// hijackHandler is called on hijacked connection.
func hijackHandler(c net.Conn) {

	var ival int32
	var msg []byte

	ival = -1
	log.Printf("hello hijack handler\n")

	defer c.Close()

	log.Println("*** ws handler start ***")

	binary := false
	ival = 0
	for it:=0; it< 10; it++ {
		header, err := ws.ReadHeader(c)
		if err != nil {log.Printf("ws error -- read header: %v\n", err)}

		log.Printf("<ws rec msg header [%d]: %x\n",header.Length,header.OpCode)
//		PrintWSHeader(header)

		if header.OpCode == ws.OpClose {
			log.Printf("ws info -- close code\n")
			break
		}
			// change
		payload := make([]byte, header.Length)
		_, err = io.ReadFull(c, payload)
		if err != nil {log.Printf("ws error -- read full: %v\n", err)}
		if header.Masked {
			ws.Cipher(payload, header.Mask, 0)
		}
		if header.OpCode == 1 {
			binary = false
			log.Printf("<ws rec text payload [%d]: >%s<\n", header.Length, payload)
		}

		if header.OpCode == 2 {
			binary = true
// x
			inval := BArToInt32(payload[:4])
//			ival = ByteSliceToInt32(payload[:4])
			log.Printf("<ws rec binary payload [%d]: >%d<\n", header.Length, inval)
//			ival = inval
		}

		if it >3 {
			binary = true
		}
		// Reset the Masked flag, server frames must not be masked as
		// RFC6455 says.
		header.Masked = false
		if binary {
//			msg = Int32ToByteSlice(ival)
			ar := Int32ToBAr(ival)
			msg = ar[:]
			fmt.Printf("msg: %v\n", msg)
			header.OpCode = 2
			header.Length = 4
		} else {
			tstStr := fmt.Sprintf("hello client %d!", it)
			msg = []byte(tstStr)
			header.Length = int64(len(msg))
			header.OpCode = 1
		}

		if it == 7 {
			header.OpCode = 1
			binary = false
			msg = []byte("end")
			header.Length = int64(len(msg))
		}

		if err := ws.WriteHeader(c, header); err != nil {
			log.Printf("error -- write header: %v\n", err)
		}
		if _, err := c.Write(msg); err != nil {
			log.Printf("error -- write payload: %v\n", err)
		}
		if binary {
			log.Printf(">bin msg sent [%d]: %d!", header.Length, ival)
			ival++
		} else {
			log.Printf(">txt msg sent [%d]: >%s<", header.Length, msg)
		}
	}


}

func PrintCtx(ctx *fasthttp.RequestCtx) {

	fmt.Println("******************** CTX request ******************")
	fmt.Printf("RequestURI is %q! Method %q\n", ctx.RequestURI(), ctx.Method())
	fmt.Printf("Requested path is %q\n", ctx.Path())
	fmt.Printf("Host is %q\n", ctx.Host())
	fmt.Printf("Query string is %q\n", ctx.QueryArgs())
	fmt.Printf("User-Agent is %q\n", ctx.UserAgent())
	fmt.Printf("Connection has been established at %s\n", ctx.ConnTime())
	fmt.Printf("Request has been started at %s\n", ctx.Time())
	fmt.Printf("Serial request number for the current connection is %d\n", ctx.ConnRequestNum())
//	fmt.Printf("Your source adr is %q\n", ctx.RemoteAddr.String())
	con:= ctx.Conn()
	adr := con.RemoteAddr()
	fmt.Printf("remote addr: %q \n", adr.String())
	idx := strings.Index(adr.String(), ":")
	port := adr.String()[idx+1:]
	fmt.Printf("port: %s\n", port)
	// unique id
	fmt.Printf("connection seq: %d\n",  ctx.ConnRequestNum())
	if ctx.ConnRequestNum() == 1 {fmt.Printf("need to login!\n")}

	fmt.Printf("connection id: %d\n\n", ctx.ConnID())

	authVal:= ctx.Request.Header.Peek("Authorization")
	fmt.Printf("auth value: %s\n", authVal)

	numHeaders := ctx.Request.Header.Len()
	head := ctx.Request.Header.RawHeaders()
	fmt.Printf("headers [%d]:\n%s\n", numHeaders, head)
	fmt.Printf("end headers\n")
	fmt.Printf("\nRaw request is:\n---START---\n%s\n---END---", &ctx.Request)

	fmt.Println("****************** End CTX request ****************")

}




func PrintWSHeader(h ws.Header) {

	fmt.Println("************* ws Header **************")
	fmt.Printf("Fin:    %t\n",h.Fin)
	fmt.Printf("Rsv:    %x\n",h.Rsv)
	fmt.Printf("OpC:    %x\n",h.OpCode)
	fmt.Printf("Masked: %t\n",h.Masked)
	fmt.Printf("Mask: 	%v\n",h.Mask)
	fmt.Printf("Length: %t\n",h.Fin)
	fmt.Println("*********** end ws Header ************")
}


func parseScript(idx []byte)(res []scrIns, err error) {

	ist :=0
	scIdx :=-1
	scEnd := -1
	for i:=0; i< 10; i++ {
		scIdx = bytes.Index(idx[ist:],[]byte("<script "))
		if scIdx == -1 {break}
		nist := ist + scIdx + 8
		scEnd = bytes.Index(idx[nist:],[]byte("</script>"))
		ist = nist + scEnd + 9
//fmt.Printf("%d: %s\n",i,string(idx[nist:ist -9]))
		fmt.Printf("check src:  %s\n", idx[nist:nist+scEnd])
		jsfilnam, err := parseScriptFil(idx[nist:(ist -9)])
		if err != nil {return res, fmt.Errorf("parsing script: %v", err)}
//fmt.Printf("js file name: %s\n", jsfilnam)
		srcIdx := bytes.Index(idx[nist:nist+scEnd], []byte("psrc="))
		if srcIdx>-1 {srcIdx=nist+ srcIdx}
		scr := scrIns {
			st: nist,
			end: ist-9,
			filnam: jsfilnam,
			src: srcIdx,
		}

		res = append(res, scr)
	}
//	if scIdx<0 {return res, fmt.Errorf("no script")}
//	if scEnd<0 {return res, fmt.Errorf("no /script")}
	return res, nil
}

func parseScriptFil(x []byte)(out string, err error) {

	istate:=0
	ist:= -1
	iend := -1
	for i:=0; i< len(x)-1; i++ {
		switch istate {
		case 0:
			if x[i] == '\'' {
				istate = 1
				ist = i+1
			}

		case 1:
			if x[i] == '\'' {
				istate = 2
				iend = i
			}
		default:
		}
		if istate == 2 {break}
	}

	if ist<0 {return "", fmt.Errorf("no start apost")}
	if iend<0 {return "", fmt.Errorf("no end apost")}

	out = string(x[ist:iend])
	return out, nil
}

func toInt(bytes []byte) int {
    result := 0
    for i := 0; i < 4; i++ {
        result = result << 8
        result += int(bytes[i])

    }

    return result
}

func Int32ToByteSlice(num int32) []byte {
    size := int(unsafe.Sizeof(num))
    arr := make([]byte, size)
    for i := 0 ; i < size ; i++ {
        byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
        arr[i] = byt
    }
    return arr
}

func ByteSliceToInt32(arr []byte) int32{
    val := int32(0)
    size := 4
    for i := 0 ; i < size ; i++ {
        *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&val)) + uintptr(i))) = arr[i]
    }
    return val
}

func Int32ToBAr(x int32) (ar [4]byte) {
	ar = *(*[4]byte)(unsafe.Pointer(&x))
	return ar
}

func BArToInt32(ar []byte) (x int32) {
	x = *(*int32)(unsafe.Pointer(&ar[0]))
	return x
}
// (*type)(unsafe.Pointer()) casts a pointer into a pointer to type 
