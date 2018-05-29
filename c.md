I [code\-golfed](https://en.wikipedia.org/wiki/Code_golf) some JavaScript \(prettied up later\) that uses a free no\-login [quantum random number API](https://qrng.anu.edu.au/) and a [comprehensive TLS certificate database](https://crt.sh/?id=488045012) to [randomly](https://en.wikipedia.org/wiki/There_are_known_knowns) [open](https://en.wiktionary.org/wiki/serendipity) past or presently [HTTPS](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https)\-[enabled](https://doesmysiteneedhttps.com/) websites \(and subdomains\) in major modern browsers. And the answer to one of your questions is [hundreds of millions](http://tvtropes.org/pmwiki/pmwiki.php/Main/SturgeonsLaw).

One should be [using](https://www.virtualbox.org/manual/ch13.html) [protection](https://en.wikipedia.org/wiki/Privacy_mode), but YOLO and Chromium warns me before risking what it *believes* is malicious... \(more on that later\)

**\>\>\>** [the line to copy\-paste](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/469.js#L1) into a JavaScript console \([Firefox help](https://developer.mozilla.org/en-US/docs/Tools/Keyboard_shortcuts), [Chrome help](https://developers.google.com/web/tools/chrome-devtools/shortcuts)\) in a blank tab/window \(`about:blank`\)

**\>\>\>** [the raw text/plain file](https://raw.githubusercontent.com/0joshuaolson1/deranged-discovery/a74a2fafd3245f80239345b6ede6353b5fad67ef/469.js) \('ignore' the n\-gram comment\)

*Lovingly tributed to* [https://www.smbc\-comics.com/comic/2014\-08\-04](https://www.smbc-comics.com/comic/2014-08-04).

# How to use

1. Ensure you have installed and enabled a [CORS extension](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#The_HTTP_response_headers) like [this for Firefox](https://addons.mozilla.org/en-US/firefox/addon/access-control-allow-origin/) and [this for Chrome](https://chrome.google.com/webstore/detail/cors/dboaklophljenpcjkbbibpkbpbobnbld).
2. Allow popups. Sorry.
3. Run the code in the console. It defines the function `c` \(for 'crt.sh' or 'certificate'\).
4. As many times as you want, **do** `c(4)` to find one certificate with high probability and open all domains registered with it \(with duplicates if e.g. `www.` redirects\).** Or**, use any higher number \(opens more certs/sites\) up t`o 10`24 due to how the RNG api works, but for your sake don't load 9000 loading tabs at on**ce. A valu**e of** **15 –** 20 each time is probably ple**nty.

Note: I wrote that some websites found by this method *used* to support https. **There's a difference between an 'insecure website' warning \(certificate error\) and a 'potential malware ahead' warning.**

# But explain the code!

**\>\>\>** [the ](https://github.com/0joshuaolson1/deranged-discovery/blob/bcea2f057cbc6b5ba3f4efe110d04562d8b2fb8b/c.js)[unminified, ](https://github.com/0joshuaolson1/deranged-discovery/blob/bcea2f057cbc6b5ba3f4efe110d04562d8b2fb8b/c.js)[syntax\-highlighted version](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js) \(and [file](https://raw.githubusercontent.com/0joshuaolson1/deranged-discovery/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js)\)

[Operator precedence reference](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Operator_Precedence).

The [request function](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js#L2-L5)'s `method` effectively defaults to `GET` in [fetch](https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/fetch). There's no error handling, and `callback` can be called with non\-200 OK status codes.

I don't think the [api](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js#L28) [queries](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js#L23) need [cache busting](https://lightignite.com/cache-busting-during-development/) because for me, both Firefox and Chromium, for some reason, insert headers that prevent caching \(even when I don't want that in real life\). The relevant RFCs are noncommittal about GET query string caching, so whatever.

The [loop](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js#L8) over an array of random bytes accumulates them in `random` and consumes them by fair [rejection sampling](https://en.wikipedia.org/wiki/Rejection_sampling#Algorithm). Bit shifts ruin numbers greater than `Math.pow(2, 31)` \(`2147483648`\), which` (5e8 - 2) * 25`6 surpasses but gets smaller than before truncation wit`h number |` 0.

When [this request](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js#L12) handler receives a [PEM](https://stackoverflow.com/a/31253562) [file](https://crt.sh/?opt=nometadata&asn1=488045012), it opens a corresponding [crt.sh](https://crt.sh) page for manual inspection if it can't find a marker near the url list length byte. Non\-leaf certificates are rare, and while they don't have "X509v3 Subject Alternative Name" sections, they often list company websites elsewhere.

Differences from the original:

* comments
* whitespace instead of semicolons
* `if` blocks instead of [ternary](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Conditional_Operator) expressions
* a sprinkling of `const`
* like the ternaries, I moved [these assignments](https://github.com/0joshuaolson1/deranged-discovery/blob/a74a2fafd3245f80239345b6ede6353b5fad67ef/c.js#L13-L14) for easier reading

**This isn't exactly a code golfing reddit, but ask/comment/suggest away.** I'm guessing to get much more minimal than 469 bytes would involve wasting quantum and network data. Nor do I want the tradeoffs of `http://` or a bigint implementation/library download to save more bytes/data.

P.S. The [ES6 specification](https://www.ecma-international.org/ecma-262/6.0/) for people who love spec\-ese. I happened not to need any later features.
