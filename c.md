# Accidentally Around the Web in 544 Characters

Ah, [JavaScript](https://www.ecma-international.org/ecma-262/6.0/). It tempted me to go [code golfing](https://en.wikipedia.org/wiki/Code_golf). I didn't need later features, but I'll be referencing [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Operator_Precedence) for convenience and browser APIs.

## The problem statement

I wanted to open [truly](https://www.av8n.com/turbid/paper/turbid.htm#sec-def-random) [random](https://en.wikipedia.org/wiki/Hardware_random_number_generator#Physical_phenomena_with_random_properties) websites in a browser in order to serendipitously discover [new things](https://en.wikipedia.org/wiki/There_are_known_knowns), like tools, concepts, and communities, with minimum possible bias. But what are 'websites'? Let's ignore the web crawler and law enforcement frontiers of the [dark web](https://en.wikipedia.org/wiki/Dark_web) and just deal with the [HTTP(S) protocol(s)](https://en.wikipedia.org/wiki/World_Wide_Web#Function). It's [mostly ICANN domain names](https://en.wikipedia.org/wiki/Alternative_DNS_root) out there, maybe, so I pretended that's enough.

## A solution

WHOIS services require already knowing a website in order to look it up. Reverse IP search has opt-in (in the registration process), robots.txt, and mention dependence problems since they rely on [indexers](https://www.domcop.com/top-10-million-domains)/[archivers](https://archive.org/). Public registrar logs aren't really a thing. [Zone data](https://dnpedia.com/tlds/daily.php) [isn't exactly open or centralized](https://www.iana.org/domains/root/db), especially for ccTLDs.

Then I found this:

> [https://crt.sh/ discovers certificates by continually monitoring all of the publicly known Certificate Transparency (CT) logs.](https://www.comodo.com/news/press_releases/2015/06/comodo-launches-new-certificate-transparency-search-web-site.html)

Afaict, basically every past (may still exist) and (almost) current TLS-enabled website (often and/or subdomains) is represented, so why not scrape [easily sampled HTML](https://crt.sh/?id=200000000) with free access to hundreds of millions of websites that might [respect](https://doesmysiteneedhttps.com/) [standards](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https)? Modern browsers can't fully protect us from IP/DNS monitoring or [boring, unpopular, unfinished](http://tvtropes.org/pmwiki/pmwiki.php/Main/SturgeonsLaw), half-untranslatable, or NSFW sites, but incognito windows help with the malicious ones that slip through the cracks, right? Implying that I use protection...

## The code

The [c.js file](https://github.com/0joshuaolson1/deranged-discovery/blob/cb5d35e632c74597263d0c65bad7312aa5efb202/c.js) ([direct/raw](https://raw.githubusercontent.com/0joshuaolson1/deranged-discovery/cb5d35e632c74597263d0c65bad7312aa5efb202/c.js)) contains 544 UTF-8/ASCII bytes excluding GitHub's newline tampering at the end ([GitLab](https://about.gitlab.com/2016/05/11/git-repository-pricing/) ftw):
```
n=5e8;r=(c,m)=>u=>fetch(u='https://'+u,m).then(r=>r.text()).then(s=>c(u,s));c=l=>r((_,d)=>{e=0;E=1;eval('_='+d).data.map(N=>{e=e%n+E*N;E*=256;e<E-E%n?(r((u,s,$='&nbsp;',_=$+$+$+$,b='<BR>'+_,e=b+_+_+_+'DNS:',i=s[f='indexOf'](b+_+_+'X509v3'+$+'Subject'+$+'Alternative'+$+'Name:'+$+e),j,S=new Set)=>{for(j=i+=~i?129:open(s.slice(-1)!=`
`?u:I)();i==j;j=s[f](e,i))S.add(s.slice(2*(s[i=j+104]=='*')+i,i=s[f](b,i)));S.forEach(r(open,{method:'HEAD'}))})('crt.sh/?id='+e%n),e=e/n|0,E=E/n|0):E%=n})})('qrng.anu.edu.au/API/jsonI.php?type=uint8&length='+l)
```
Unminified:
```
 1|idRange = 5e8
 2|
```

Type and run `c(4)`, named after 'certificate' or `crt.sh`, or use a bigger number ≤ 1024 to open more sites with high probability. Allow popups from [`about:blank`](http://about:blank) (you'll have to copy/type that in Firefox) and use a CORS workaround like [this](https://chrome.google.com/webstore/detail/cors/dboaklophljenpcjkbbibpkbpbobnbld) so `c` can access webpages. I've tested it in Chromium and Firefox.

So how does it work? I'm glad you asked!
```
 3|request = (url, callbackCtor) =>
 4|    fetch(url)
 5|    .then(response => response.text())
 6|    .then(callbackCtor(url))
 7|c = rngByteCount => request(
```
`c` is a one-parameter [arrow function](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/Arrow_functions) that requests `4` or whatever bytes from a quantum random number API. `request` is a separate function (taking a callback) because inlining/specializing it in the two places where it's used would be more verbose (as would [promises](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises) or [async/await](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function)).

The [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) does use promises (without error handling), and it's more concise than [XHR](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest). The first `then` function runs if the website returns something, even an error code. The last `then` function

https://tools.ietf.org/html/rfc7127#section-2
https://tools.ietf.org/html/rfc7234#section-4.2.2
https://stackoverflow.com/questions/49547/how-to-control-web-page-caching-across-all-browsers/99183#99183
