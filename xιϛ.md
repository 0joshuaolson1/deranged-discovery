# Accidentally around the HTTPS world in 616 characters

Ah, [JavaScript](https://www.ecma-international.org/ecma-262/6.0/). It tempted me to go [code golfing](https://en.wikipedia.org/wiki/Code_golf). I had no need for later features, but I'll be referencing [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Operator_Precedence) for convenience, browser APIs, and the confidence that the code works with other standards/implementations besides in non-Chrom(e|ium) browsers.

## The problem statement

I wanted to open [truly](https://www.av8n.com/turbid/paper/turbid.htm#sec-def-random) [random](https://en.wikipedia.org/wiki/Hardware_random_number_generator#Physical_phenomena_with_random_properties) websites in a browser in order to serendipitously discover [new things](https://en.wikipedia.org/wiki/There_are_known_knowns), like tools, concepts, and communities, with minimum possible bias. But what are 'websites'? Let's ignore the web crawler and law enforcement frontiers of the [dark web](https://en.wikipedia.org/wiki/Dark_web) and just deal with the [HTTP(S) protocol(s)](https://en.wikipedia.org/wiki/World_Wide_Web#Function). It's [mostly ICANN domain names](https://en.wikipedia.org/wiki/Alternative_DNS_root) out there, maybe, so I pretended that's enough.

## A solution

WHOIS services require already knowing a website in order to look it up. Reverse IP search has opt-in (in the registration process), robots.txt, and mention dependence problem since they rely on [indexers](https://www.domcop.com/top-10-million-domains)/[archivers](https://archive.org/). Public registrar logs aren't really a thing. [Zone data](https://dnpedia.com/tlds/daily.php) [isn't exactly open or centralized](https://www.iana.org/domains/root/db), especially ccTLDs.

Then I found this:

> [https://crt.sh/ discovers certificates by continually monitoring all of the publicly known Certificate Transparency (CT) logs.](https://www.comodo.com/news/press_releases/2015/06/comodo-launches-new-certificate-transparency-search-web-site.html)

Afaict, every past (may still exist) and (almost) current TLS-enabled website (often and/or subdomains) is represented, so why not scrape [easily sampled HTML](https://crt.sh/?id=200000000) with free access to hundreds of millions of websites that might [respect](https://doesmysiteneedhttps.com/) [standards](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https)? Modern browsers can't fully protect us from IP/DNS monitoring or [boring, unpopular, unfinished](http://tvtropes.org/pmwiki/pmwiki.php/Main/SturgeonsLaw), half-untranslatable, or NSFW sites, but incognito windows help with the malicious ones that slip through the cracks, right? Implying that I use protection...

# The code

The [c.js file](https://github.com/0joshuaolson1/deranged-discovery/blob/master/c.js) ([direct permalink](https://raw.githubusercontent.com/0joshuaolson1/deranged-discovery/e2bdfe3eccf131ea128840ac918800e930389414/c.js)) contains 616 UTF-8/ASCII bytes including the blatant fudge of GitHub's enforced ending newline ([GitLab](https://about.gitlab.com/2016/05/11/git-repository-pricing/) ftw):
```
n=5e8;h='https://';r=(u,c)=>fetch(u).then(r=>r.text()).then(c(u));c=l=>r(h+'qrng.anu.edu.au/API/jsonI.php?z='+Date.now()+'&type=uint8&length='+l,u=>(d,_)=>{for(d=JSON.parse(d).data,e=0,E=1;e<E-E%n?(r(h+'crt.sh/?id='+e%n,u=>(s,$='&nbsp;',_=$+$+$+$,b='<BR>'+_,e=b+_+_+_+'DNS:',i=s.search(b+_+_+'X509v3'+$+'Subject'+$+'Alternative'+$+'Name:'+$+e),j,S=new Set)=>{for(j=i+=s.slice(-1)==`
`||i<0&&open(u)?I:129;i==j;j=s.indexOf(e,i))S.add(h+s.slice(2*(s[i=j+104]=='*')+i,i=s.indexOf(b,i)));S.forEach(s=>fetch(s,{method:'HEAD'}).then(_=>open(s)))}),e=e/n|0,E=E/n|0):E%=n;)for(e%=n;E<n;E*=256)e+=E*(d.length?d.pop():_[E])})
```
Unminified:
```
 1|idRange = 5e8
 2|prefix = 'https://'
 3|request = (url, callbackCtor) =>
 4|    fetch(url)
 5|    .then(response => response.text())
 6|    .then(callbackCtor(url))
 7|c = rngByteCount => request(
 8|    prefix + 'qrng.anu.edu.au/API/jsonI.php?z=' + Date.now()
 9|    + '&type=uint8&length=' + rngByteCount
10|    , _unused => (rngData, undefined) => {
11|        for(
12|            rngData = JSON.parse(rngData).data, entropyValue = 0, entropyRange = 1
13|            ; entropyValue < entropyRange - entropyRange % idRange
14|                ? (
15|                    request(
16|                        prefix + 'crt.sh/?id=' + entropyValue % idRange
17|                        , url =>
18|                            (
19|                                html
20|                                , space = '&nbsp;'
21|                                , spaces = space + space + space + space
22|                                , brSpace = '<BR>' + space
23|                                , label = brSpace + spaces + spaces + spaces + 'DNS:'
24|                                , lineIndex = html.search(
25|                                    brSpace + spaces + spaces + 'X509v3' + space
26|                                    + 'Subject' + space + 'Alternative' + space + 'Name:' + space + label
27|                                ), domainIndex
28|                                , domains = new Set
29|                            ) => {
30|                                for(
31|                                    domainIndex = lineIndex +=
32|                                        html.slice(-1) == `
33|                                        ||
34|                                        i < 0 && open(url)
35|                                            ? I
36|                                            : 129
37|                                    ; lineIndex == domainIndex
38|                                    ; domainIndex = html.indexOf(label, lineIndex)
39|                                )
40|                                    domains.add(prefix + html.slice(
41|                                        2 * (
42|                                            html[lineIndex=domainIndex+104] == '*'
43|                                        ) + lineIndex
44|                                        , lineIndex = html.indexOf(brSpace, lineIndex)
45|                                    ))
46|                                ; domains.forEach(domain =>
47|                                    fetch(domain, {method: 'HEAD'})
48|                                    .then(_unused => open(domain))
49|                                )
50|                            }
51|                    ), entropyValue = entropyValue/idRange | 0
52|                    , entropyRange = entropyRange/idRange | 0
53|                ) : entropyRange %= idRange
54|        ;)
55|            for(
56|                entropyValue %= idRange
57|                ; entropyRange < idRange
58|                ; entropyRange *= 256
59|            )
60|                entropyValue += entropyRange * (
61|                    rngData.length
62|                        ? rngData.pop()
63|                        : undefined[entropyRange]
64|                )
65|    }
66|)
```

You're supposed to evaluate something like `c(4)` (bigger numbers open more sites with high probability), named after 'certificate' or `crt.sh`. The [Chrome Devtools console](https://developers.google.com/web/tools/chrome-devtools/shortcuts) is ideal due to an intentional error message explained later. In any case, you'll need to run this in something like [about:blank](about:blank) with a [CORS workaround](https://chrome.google.com/webstore/detail/cors/dboaklophljenpcjkbbibpkbpbobnbld) so it can access webpages.

How does it work? I'm glad you asked!
```
```
