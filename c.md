# Accidentally Around the Web in 544 Characters

Ah, [JavaScript](https://www.ecma-international.org/ecma-262/6.0/). It tempted me to go [code golfing](https://en.wikipedia.org/wiki/Code_golf). I didn't need later features, but I'll be referencing the cross-edition [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Operator_Precedence) for convenience and browser APIs.

## The problem statement

I wanted to open [truly](https://www.av8n.com/turbid/paper/turbid.htm#sec-def-random) [random](https://en.wikipedia.org/wiki/Hardware_random_number_generator#Physical_phenomena_with_random_properties) websites in a browser in order to serendipitously discover [new things](https://en.wikipedia.org/wiki/There_are_known_knowns), like tools, concepts, and communities, with minimum possible bias. But what are 'websites'? Let's ignore the web crawler and law enforcement frontiers of the [dark web](https://en.wikipedia.org/wiki/Dark_web) and just deal with the [HTTP(S) protocol(s)](https://en.wikipedia.org/wiki/World_Wide_Web#Function). It's [mostly ICANN domain names](https://en.wikipedia.org/wiki/Alternative_DNS_root) out there, maybe, so I pretended that's enough.

## A solution

WHOIS services require already knowing a website in order to look it up. Reverse IP search has opt-in (in the registration process), robots.txt, and mention-dependence problems since they rely on [indexers](https://www.domcop.com/top-10-million-domains)/[archivers](https://archive.org/). Public registrar logs aren't really a thing. [Zone data](https://dnpedia.com/tlds/daily.php) [isn't exactly open or centralized](https://www.iana.org/domains/root/db), especially for ccTLDs.

Then I found this:

> [https://crt.sh/ discovers certificates by continually monitoring all of the publicly known Certificate Transparency (CT) logs.](https://www.comodo.com/news/press_releases/2015/06/comodo-launches-new-certificate-transparency-search-web-site.html)

Afaict, basically all past (possibly existing) and (almost) current TLS-enabled websites (often and/or subdomains) are included, so why not scrape [easily sampled HTML](https://crt.sh/?id=200000000) with free access to hundreds of millions of websites that might [respect](https://doesmysiteneedhttps.com/) [standards](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https)? Modern browsers can't fully protect us from IP/DNS monitoring/hijacking or sites that are [boring, unpopular, unfinished](http://tvtropes.org/pmwiki/pmwiki.php/Main/SturgeonsLaw), NSFW, or half-untranslatable, but incognito windows help with the malicious ones that slip through the defenses, right? Implying that I use protection...

## The code

The [c.js file](https://github.com/0joshuaolson1/deranged-discovery/blob/cb5d35e632c74597263d0c65bad7312aa5efb202/c.js) (or [direct link](https://raw.githubusercontent.com/0joshuaolson1/deranged-discovery/cb5d35e632c74597263d0c65bad7312aa5efb202/c.js)) contains 544 copy-pastable UTF-8/ASCII bytes excluding GitHub's newline tampering at the end ([GitLab](https://about.gitlab.com/2016/05/11/git-repository-pricing/) ftw):
```
n=5e8;r=(c,m)=>u=>fetch(u='https://'+u,m).then(r=>r.text()).then(s=>c(u,s));c=l=>r((_,d)=>{e=0;E=1;eval('_='+d).data.map(N=>{e=e%n+E*N;E*=256;e<E-E%n?(r((u,s,$='&nbsp;',_=$+$+$+$,b='<BR>'+_,e=b+_+_+_+'DNS:',i=s[f='indexOf'](b+_+_+'X509v3'+$+'Subject'+$+'Alternative'+$+'Name:'+$+e),j,S=new Set)=>{for(j=i+=~i?129:open(s.slice(-1)!=`
`?u:I)();i==j;j=s[f](e,i))S.add(s.slice(2*(s[i=j+104]=='*')+i,i=s[f](b,i)));S.forEach(r(open,{method:'HEAD'}))})('crt.sh/?id='+e%n),e=e/n|0,E=E/n|0):E%=n})})('qrng.anu.edu.au/API/jsonI.php?type=uint8&length='+l)
```
Allow popups from [`about:blank`](http://about:blank) (you'll have to copy/type that if using Firefox) and use a CORS workaround like [this](https://chrome.google.com/webstore/detail/cors/dboaklophljenpcjkbbibpkbpbobnbld) so the code can access webpages. Paste the code into `about:blank`'s [JavaScript](https://developer.mozilla.org/en-US/docs/Tools/Keyboard_shortcuts) [console](https://developers.google.com/web/tools/chrome-devtools/shortcuts). Then type and run `c(4)` (named after the 'certificate' in '`crt`') as many times as you'd like (with some patience for network requests), or use a bigger number ≤ 1024 to open more sites with high probability.  I've only tested it in Chromium and Firefox with a reliable internet connection when both of the two websites used to do this have been cooperative.

That's the instructions. From here on is an explanation justifying the identical unminified code:
```
 1|idRange = 5e8;
 2|request = (callback, method) => url =>
 3|    fetch(url = 'https://' + url, method)
 4|    .then(response => response.text())
 5|    .then(text => callback(url, text));
 6|c = rngByteCount => request((_unused, rngBytes) => {
 7|    entropyValue=0;
 8|    entropyRange=1;
 9|    eval('_=' + rngBytes).data.map(rngByte => {
10|        entropyValue = entropyValue%idRange + entropyRange*rngByte;
11|        entropyRange *= 256;
12|        entropyValue < entropyRange - entropyRange%idRange
13|            ? (
14|                request(
15|                    (
16|                        url,
17|                        html,
18|                        space = '&nbsp;',
19|                        spaces = space + space + space + space,
20|                        br = '<BR>' + spaces,
21|                        label = br + spaces + spaces + spaces + 'DNS:',
22|                        lineIndex = html[indexOf = 'indexOf'](br + spaces + spaces + 'X509v3' + space + 'Subject' + space + 'Alternative' + space + 'Name:' + space + label),
23|                        domainIndex,
24|                        set = new Set
25|                    ) => {
26|                        for(
27|                            domainIndex = lineIndex += ~i
28|                                ? 129
29|                                : open(
30|                                    html.slice(-1) != `
31|`                                       ? url : ERROR
32|                                )();
33|                            lineIndex == domainIndex;
34|                            domainIndex = html[indexOf](label, lineIndex)
35|                        )
36|                            set.add(html.slice(
37|                                2*(html[lineIndex = domainIndex + 104] == '*') + i,
38|                                lineIndex = html[indexOf](br, lineIndex)
39|                            ));
40|                        set.forEach(request(open, {method: 'HEAD'}))
41|                    }
42|                )('crt.sh/?id=' + entropValue%idRange),
43|                entropyValue = entropyValue/idRange | 0,
44|                entropeRange = entropyRange/idRange | 0
45|            ) : entropyRange %= idRange
46|    })
47|})('qrng.anu.edu.au/API/jsonI.php?type=uint8&length=' + rngByteCount)
```

First, `c`'s definition (with [arrow function syntax](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/Arrow_functions)):
```
 6|c = rngByteCount => request((_unused, rngBytes) => {
...
47|})('qrng.anu.edu.au/API/jsonI.php?type=uint8&length=' + rngByteCount)
```
It passes its only argument `rngByteCount` to a `request` function to get that many bytes from the only free no-signup [quantum random number api](https://qrng.anu.edu.au/API/api-demo.php) I know of.

`request` takes a callback function to handle the response text `rngBytes`, then 'takes' the api's url (the missing '`https://`' will be taken care of) in an unusual way - by evaluating a [partially applied](http://wiki.c2.com/?CurryingSchonfinkelling) function returned by `request`. `request` works this way because it shortens the code enough in another place it'll be used.


Now for `request`:
```
 2|request = (callback, method) => url =>
 3|    fetch(url = 'https://' + url, method)
 4|    .then(response => response.text())
 5|    .then(text => callback(url, text));
```
It uses the [fetch api](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) instead of the older, more verbose [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) object. `request` passes its `method` argument to `fetch`, which defaults to doing an HTTP GET with the `url` when `method` is `undefined` as when `c` only provides `callback`.

Every requested `url` in the code gets to omit `https://`, which the now local variable `url` is freely modified to include for the callback's benefit. Also, the '`.then`' [Promise chain](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) doesn't handle errors like certain HTTP status codes - instead of trusting them, `callback` runs as long as the site responds with something. If `c` can't get its random bytes from `text`, it'll stop with an exception anyway.

https://tools.ietf.org/html/rfc7127#section-2
https://tools.ietf.org/html/rfc7234#section-4.2.2
https://stackoverflow.com/questions/49547/how-to-control-web-page-caching-across-all-browsers/99183#99183
