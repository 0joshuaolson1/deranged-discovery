r=(u,c,x=new XMLHttpRequest())=>{x.open('GET',u='https://'+u);x.onload=_=>{try{c(JSON.parse(x=x.response).data)}catch(_){c(x,u)}};x.send()};c=l=>r('qrng.anu.edu.au/API/jsonI.php?z='+Date.now()+'&type=uint8&length='+l,(d,n=5e8,_)=>{for(e=0,E=1;e<E-E%n?(r('crt.sh/?id='+e%n,(s,u,$='&nbsp;',_=$+$+$+$,b='<BR>'+_,e=b+_+_+_+'DNS:',i=s.search(b+_+_+'X509v3'+$+'Subject'+$+'Alternative'+$+'Name:'+$+e),j)=>{if(s.slice(-1)=='\n')return;if(i<0)return open(u);for(j=i+=129;i==j;j=s.indexOf(e,i))open(s.slice(i=j+104,i=s.indexOf(b,i)))}),e=e/n|0,E=E/n|0):E%=n;)for(e%=n;E<n;E*=256)e+=E*(d.length?d.pop():_[E])})
