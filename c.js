const RANGE = 5e8
const request = (callback, method) => url => 
    fetch(url = 'https://' + url, method)
    .then(response => response.text())
    .then(text => callback(url, text))
c = rngByteCount =>
    request((_, text, random = 0, entropy = 1) =>                                   /*
    */  eval('_=' + text).data.map(rngByte => {                                     /*
    *   */  random = random % RANGE + entropy * rngByte                             /*
    *   */  entropy *= 256                                                          /*
    *   */  if(random < entropy - entropy % RANGE){                                 /*
    *   *   */  request((url, base64) => {                                          /*
    *   *   *   */  const blob = atob(base64.slice(27, -26))                        /*
    *   *   *   */  const offset = blob.search('')                              /*
    *   *   *   */  if(~offset)                                                     /*
    *   *   *   *   */  new Set(                                                    /*
    *   *   *   *   *   */  blob.substr(offset + 6, blob.charCodeAt(offset + 4) - 1)/*
    *   *   *   *   *   */  .split('').map(domain =>                              /*
    *   *   *   *   *   *   */  domain.slice(domain[1] == '*' ? 3 : 1)              /*
    *   *   *   *   *   */  )                                                       /*
    *   *   *   *   */  ).forEach(request(open, {method: 'HEAD'}))                  /*
    *   *   *   */  else open(url.slice(0, 16) + 'opt=nometadata&i' + u.slice(16))  /*
    *   *   */  )('crt.sh/?d=' + random % RANGE)                                    /*
    *   *   */  random = random/RANGE | 0                                           /*
    *   *   */  entropy = entropy/RANGE | 0                                         /*
    *   */  } else entropy %= RANGE                                                 /*
    */  })
    )('qrng.anu.edu.au/API/jsonI.php?type=uint8&length='+l)
