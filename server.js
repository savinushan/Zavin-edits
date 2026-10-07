const express=require('express'),multer=require('multer'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PASS=process.env.ADMIN_PASSWORD||'zavin123', PORT=process.env.PORT||3000;
const DATA=path.join(__dirname,'data'),UP=path.join(__dirname,'uploads'),DB=path.join(DATA,'videos.json');
[DATA,UP].forEach(d=>fs.mkdirSync(d,{recursive:true}));
if(!fs.existsSync(DB))fs.writeFileSync(DB,'[]');
const read=()=>JSON.parse(fs.readFileSync(DB)),write=v=>fs.writeFileSync(DB,JSON.stringify(v,null,2));
const sha=s=>crypto.createHash('sha256').update(String(s)).digest();
const sessions=new Set();
const tok=r=>((r.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('zt='))||'').slice(3);
const auth=(q,s,n)=>sessions.has(tok(q))?n():s.status(401).json({error:'Login first'});
const upload=multer({
  storage:multer.diskStorage({destination:UP,filename:(q,f,cb)=>cb(null,Date.now()+'-'+crypto.randomBytes(3).toString('hex')+path.extname(f.originalname).toLowerCase())}),
  limits:{fileSize:1024*1024*1024},
  fileFilter:(q,f,cb)=>cb(null,/^video\//.test(f.mimetype))
});
const app=express();
app.use(express.json());
app.use('/uploads',express.static(UP));
app.use(express.static(path.join(__dirname,'public')));
app.get('/admin',(q,s)=>s.sendFile(path.join(__dirname,'public','admin.html')));

app.get('/api/videos',(q,s)=>s.json(read().reverse()));
app.get('/api/me',(q,s)=>s.json({admin:sessions.has(tok(q))}));
app.post('/api/login',(q,s)=>{
  if(!crypto.timingSafeEqual(sha(q.body.password),sha(PASS)))return s.status(401).json({error:'Wrong password'});
  const t=crypto.randomBytes(24).toString('hex');sessions.add(t);
  s.setHeader('Set-Cookie',`zt=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`);s.json({ok:true});
});
app.post('/api/logout',(q,s)=>{sessions.delete(tok(q));s.setHeader('Set-Cookie','zt=; Path=/; Max-Age=0');s.json({ok:true})});
app.post('/api/videos',auth,upload.single('video'),(q,s)=>{
  if(!q.file)return s.status(400).json({error:'Choose a video file'});
  const v={id:crypto.randomBytes(4).toString('hex'),title:(q.body.title||'Untitled').slice(0,80),category:(q.body.category||'General').slice(0,30),description:(q.body.description||'').slice(0,300),file:'/uploads/'+q.file.filename,date:new Date().toISOString()};
  const all=read();all.push(v);write(all);s.json(v);
});
app.delete('/api/videos/:id',auth,(q,s)=>{
  const all=read(),v=all.find(x=>x.id===q.params.id);if(!v)return s.status(404).json({error:'Not found'});
  fs.unlink(path.join(UP,path.basename(v.file)),()=>{});write(all.filter(x=>x.id!==v.id));s.json({ok:true});
});
app.listen(PORT,()=>console.log(`Zavin Edits running -> http://localhost:${PORT}  (admin: /admin)`));
