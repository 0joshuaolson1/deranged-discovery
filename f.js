try{N}catch(_){N=500000n;e=0n;E=1n;h='https://'}for(e+=E*BigInt('0x'+(await(await fetch(h+'qrng.anu.edu.au/API/jsonI.php?&type=hex16&length=1&size=256')).json(E*=16n**512n)).data[0]);E>=N;e/=N,E/=N)fetch(h+'fimfiction.net/story/download/'+e%N+'/html',{method:'HEAD'}).then(r=>r.ok&&open(r.url))
