r=(u,c,m,x=new XMLHttpRequest())=>{
	x.open(m||'GET',u)
	x.onreadystatechange=_=>x.readyState<4?0:c(m?x.status:JSON.parse(x.response))
	x.send()}
q=u=>n=>l=>r('https://qrng.anu.edu.au/API/jsonI.php?time='+Date.now()+'&type=uint8&length='+l,x=>{
	for(d=x.data,e=0,E=1;;)
		if(E<n){
			if(!d.length)return console.log(E)
			e=e*256+parseInt(d.pop())
			E*=256}
		else if(e<(w=E-E%n)){
			let U='https://'+u(e%n)
			r(U,x=>x>200?0:open(U),'HEAD')
			e=Math.floor(e/n)
			E=Math.floor(E/n)}
		else{
			e-=w
			E-=w}})
f=q(n=>'www.fimfiction.net/story/download/'+n+'/html')(4e5)
s=q(n=>'w.soundcloud.com/player/?url=http://api.soundcloud.com/tracks/'+n)(5e8)
