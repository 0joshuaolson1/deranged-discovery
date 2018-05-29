const RANGE = 5e8                                    // 500 000 000 is enough in 2018
const request = (callback, method) => url =>         // use CORS mod, blank tab (CSP)
    fetch(url = 'https://' + url, method)
    .then(response => response.text())
    .then(text => callback(url, text))
const c = rngByteCount =>                            // use c(4 to 1024)
    request((_, text, random = 0, entropy = 1) => eval('_=' + text).data.map(
        rngByte => {
            random = random % RANGE + entropy * rngByte
      /* */ entropy *= 256
            if(random < entropy - entropy % RANGE){
                request((url, base64) => {
      /* */   /* */ const blob = atob(base64.slice(27, -26))
                    const offset = blob.search('') // 0x11, 0x04
                    if(~offset)
      /* */   /* */     new Set(
                            blob.substr(offset + 6, blob.charCodeAt(offset + 4) - 1)
                            .split('').map(         // 0x82
      /* */   /* */             domain => domain.slice(domain[1] == '*' ? 3 : 1)
                            )
                        ).forEach(request(open, {method: 'HEAD'}))
      /* */   /* */ else open(url.slice(0, 16) + 'opt=nometadata&i' + u.slice(16))
                })('crt.sh/?d=' + random % RANGE)
                random = random/RANGE | 0
      /* */     entropy = entropy/RANGE | 0
            } else entropy %= RANGE
        }
    ))('qrng.anu.edu.au/API/jsonI.php?type=uint8&length='+l)
