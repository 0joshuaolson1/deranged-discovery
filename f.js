N=500000n;h='https://';for(e=BigInt('0x'+await(await fetch(h+'qrng.anu.edu.au/API/jsonI.php?&type=hex16&length=1&size=256')).json(E=16n**512n).data[0]);E>=N;e/=N,E/=N)(u=>fetch(u,{method:'HEAD'}).then(r=>r.ok&&open(u)))(h+'fimfiction.net/story/download/'+e%N+'/html')
