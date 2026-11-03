const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { handleUpload } = require("@vercel/blob/client");
const { get } = require("@vercel/blob");
const { Readable } = require("stream");

const pool = global.__icmrisPool || new Pool({
  connectionString: process.env.DATABASE_URL, max: 5,
  idleTimeoutMillis: 10000, connectionTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: false }
});
global.__icmrisPool = pool;
const COOKIE = "icmris_session";
const json = (res,status,data) => { res.statusCode=status; res.setHeader("Content-Type","application/json; charset=utf-8"); res.end(JSON.stringify(data)); };
const readBody = async (req) => { if(req.body&&typeof req.body==="object")return req.body; let raw=""; for await(const c of req)raw+=c; if(!raw)return {}; try{return JSON.parse(raw)}catch{throw Object.assign(new Error("Invalid JSON body"),{status:400})} };
const cookies = (req) => Object.fromEntries((req.headers.cookie||"").split(";").map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf("=");return [x.slice(0,i),decodeURIComponent(x.slice(i+1))]}));
const setCookie = (res,token) => res.setHeader("Set-Cookie",COOKIE+"="+encodeURIComponent(token)+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800");
const clearCookie = (res) => res.setHeader("Set-Cookie",COOKIE+"=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
const sign = (u) => jwt.sign({sub:u.id,role:u.role,email:u.email},process.env.JWT_SECRET,{expiresIn:"7d"});
async function session(req){const token=cookies(req)[COOKIE];if(!token)return null;try{const p=jwt.verify(token,process.env.JWT_SECRET);const r=await pool.query("SELECT id,full_name,email,role,affiliation,phone,country,is_active FROM users WHERE id=$1",[p.sub]);return r.rows[0]?.is_active?r.rows[0]:null}catch{return null}}
const requireUser=async(req,res,roles=[])=>{const u=await session(req);if(!u){json(res,401,{error:"Please sign in to continue."});return null}if(roles.length&&!roles.includes(u.role)){json(res,403,{error:"You do not have permission for this action."});return null}return u};
const audit=(actor,action,type,id,metadata={},req)=>pool.query("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,metadata,ip_address) VALUES($1,$2,$3,$4,$5,$6)",[actor?.id||null,action,type||null,id||null,JSON.stringify(metadata),req?.headers["x-forwarded-for"]?.split(",")[0]||null]).catch(()=>{});
const email=v=>String(v||"").trim().toLowerCase();
const validEmail=v=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const uuid=v=>/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(v||""));
const makePaperCode=()=>"ICMRIS27-"+crypto.randomBytes(4).toString("hex").toUpperCase();

module.exports=async function handler(req,res){
 res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");res.setHeader("Cache-Control","no-store");
 if(req.method==="OPTIONS"){res.setHeader("Allow","GET,POST,PATCH,DELETE,OPTIONS");return res.status(204).end()}
 const url=new URL(req.url,"https://icmris-2027.vercel.app");const path=url.pathname.replace(/^\/api\/?/,"").replace(/\/$/,"");
 try{
  if(!process.env.DATABASE_URL||!process.env.JWT_SECRET)return json(res,503,{error:"Backend environment is not configured."});
  if(path==="health"&&req.method==="GET"){const r=await pool.query("SELECT NOW() AS database_time,current_database() AS database_name");return json(res,200,{ok:true,service:"ICMRIS–2027 API",database:r.rows[0].database_name,time:r.rows[0].database_time})}
  if(path==="auth/register"&&req.method==="POST"){
   const b=await readBody(req),name=String(b.fullName||"").trim(),mail=email(b.email),pw=String(b.password||"");
   if(name.length<2||!validEmail(mail)||pw.length<10)return json(res,400,{error:"Enter your name, valid email and a password of at least 10 characters."});
   const hash=await bcrypt.hash(pw,12);const r=await pool.query("INSERT INTO users(full_name,email,password_hash,role,affiliation,phone,country) VALUES($1,$2,$3,'author',$4,$5,$6) RETURNING id,full_name,email,role,affiliation,phone,country",[name,mail,hash,String(b.affiliation||"").trim()||null,String(b.phone||"").trim()||null,String(b.country||"").trim()||null]);
   setCookie(res,sign(r.rows[0]));await audit(r.rows[0],"account.registered","user",r.rows[0].id,{},req);return json(res,201,{user:r.rows[0]})
  }
  if(path==="auth/login"&&req.method==="POST"){
   const b=await readBody(req),mail=email(b.email),pw=String(b.password||"");const r=await pool.query("SELECT id,full_name,email,password_hash,role,affiliation,phone,country,is_active FROM users WHERE email=$1",[mail]);
   if(!r.rows[0]||!r.rows[0].is_active||!(await bcrypt.compare(pw,r.rows[0].password_hash)))return json(res,401,{error:"Invalid email or password."});
   const u=r.rows[0];delete u.password_hash;setCookie(res,sign(u));await audit(u,"auth.login","user",u.id,{},req);return json(res,200,{user:u})
  }
  if(path==="auth/logout"&&req.method==="POST"){clearCookie(res);return json(res,200,{ok:true})}
  if(path==="auth/me"&&req.method==="GET"){const u=await session(req);return u?json(res,200,{user:u}):json(res,401,{error:"Not signed in"})}
  if(path==="admin/bootstrap"&&req.method==="POST"){
   const b=await readBody(req);if(!process.env.ADMIN_BOOTSTRAP_SECRET||b.bootstrapSecret!==process.env.ADMIN_BOOTSTRAP_SECRET)return json(res,403,{error:"Invalid bootstrap secret."});
   const n=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'");if(n.rows[0].n>0)return json(res,409,{error:"An administrator already exists. Ask an existing admin to create accounts."});
   const name=String(b.fullName||"").trim(),mail=email(b.email),pw=String(b.password||"");if(name.length<2||!validEmail(mail)||pw.length<12)return json(res,400,{error:"Provide name, valid email and a password of at least 12 characters."});
   const hash=await bcrypt.hash(pw,12);const r=await pool.query("INSERT INTO users(full_name,email,password_hash,role) VALUES($1,$2,$3,'admin') RETURNING id,full_name,email,role",[name,mail,hash]);setCookie(res,sign(r.rows[0]));await audit(r.rows[0],"admin.bootstrap","user",r.rows[0].id,{},req);return json(res,201,{user:r.rows[0],message:"First administrator created. Bootstrap is now permanently closed."})
  }
  if(path==="newsletter"&&req.method==="POST"){const b=await readBody(req),mail=email(b.email);if(!validEmail(mail))return json(res,400,{error:"Enter a valid email address."});await pool.query("INSERT INTO newsletter_subscribers(email) VALUES($1) ON CONFLICT(email) DO UPDATE SET is_active=TRUE",[mail]);return json(res,201,{ok:true,message:"You are subscribed to conference updates."})}
  if(path==="announcements"&&req.method==="GET"){const r=await pool.query("SELECT id,title,body,published_at FROM announcements WHERE is_published=TRUE ORDER BY published_at DESC NULLS LAST,created_at DESC");return json(res,200,{announcements:r.rows})}
  if(path==="files"&&req.method==="GET"){
   const u=await requireUser(req,res,["author","reviewer","admin"]);if(!u)return;const fileId=url.searchParams.get("id");if(!uuid(fileId))return json(res,400,{error:"Invalid file reference."});
   const r=await pool.query("SELECT f.*,s.author_id FROM submission_files f JOIN submissions s ON s.id=f.submission_id WHERE f.id=$1",[fileId]);if(!r.rowCount)return json(res,404,{error:"File not found."});const f=r.rows[0];
   if(u.role==="author"&&f.author_id!==u.id)return json(res,403,{error:"You cannot access this manuscript."});
   if(u.role==="reviewer"){const assigned=await pool.query("SELECT 1 FROM reviewer_assignments WHERE submission_id=$1 AND reviewer_id=$2",[f.submission_id,u.id]);if(!assigned.rowCount)return json(res,403,{error:"This manuscript is not assigned to you."});}
   const blob=await get(f.storage_key,{access:"private"});if(!blob)return json(res,404,{error:"Stored manuscript not found."});res.setHeader("Content-Type",blob.blob.contentType||"application/pdf");res.setHeader("Content-Disposition","inline; filename="+encodeURIComponent(f.file_name));return Readable.fromWeb(blob.stream).pipe(res);
  }

  if(path==="payment-proofs"&&req.method==="GET"){
   const u=await requireUser(req,res,["author","admin"]);if(!u)return;const fileId=url.searchParams.get("id");if(!uuid(fileId))return json(res,400,{error:"Invalid payment proof reference."});
   const r=await pool.query("SELECT p.*,r.user_id AS owner_id FROM payment_proofs p JOIN registrations r ON r.id=p.registration_id WHERE p.id=$1",[fileId]);if(!r.rowCount)return json(res,404,{error:"Payment proof not found."});const f=r.rows[0];if(u.role!=="admin"&&f.owner_id!==u.id)return json(res,403,{error:"You cannot access this payment proof."});
   const blob=await get(f.storage_key,{access:"private"});if(!blob)return json(res,404,{error:"Stored payment screenshot not found."});res.setHeader("Content-Type",blob.blob.contentType||"application/octet-stream");res.setHeader("Content-Disposition","inline; filename=payment-proof");return Readable.fromWeb(blob.stream).pipe(res);
  }
  if(path==="payment-proof-upload"&&req.method==="POST"){
   const u=await requireUser(req,res,["author"]);if(!u)return;if(!process.env.BLOB_READ_WRITE_TOKEN)return json(res,503,{error:"Private file storage is not configured."});
   return await handleUpload({request:req,body:await readBody(req),onBeforeGenerateToken:async(pathname,clientPayload)=>{let m={};try{m=JSON.parse(clientPayload||"{}")}catch{}const utr=String(m.utrNumber||"").trim().toUpperCase();if(!uuid(m.registrationId)||! /^[A-Z0-9]{8,24}$/.test(utr))throw new Error("Enter a valid UTR / transaction reference (8–24 letters or digits).");const own=await pool.query("SELECT id,amount_paise,status FROM registrations WHERE id=$1 AND user_id=$2",[m.registrationId,u.id]);if(!own.rowCount)throw new Error("Registration not found.");if(Number(own.rows[0].amount_paise)<=0)throw new Error("The registration fee is not configured yet.");if(own.rows[0].status==="confirmed")throw new Error("This registration is already confirmed.");const dup=await pool.query("SELECT id FROM payment_proofs WHERE utr_number=$1",[utr]);if(dup.rowCount)throw new Error("This UTR has already been submitted.");return {access:"private",allowedContentTypes:["image/jpeg","image/png","image/webp"],maximumSizeInBytes:6*1024*1024,addRandomSuffix:true,tokenPayload:JSON.stringify({registrationId:m.registrationId,userId:u.id,utrNumber:utr})}},onUploadCompleted:async({blob,tokenPayload})=>{const m=JSON.parse(tokenPayload||"{}");const r=await pool.query("INSERT INTO payment_proofs(registration_id,user_id,utr_number,screenshot_url,storage_key) VALUES($1,$2,$3,$4,$5) RETURNING id",[m.registrationId,m.userId,m.utrNumber,blob.url,blob.pathname]);await pool.query("INSERT INTO payments(registration_id,provider,provider_payment_id,amount_paise,currency,status,receipt_url) SELECT id,'manual_upi',$2,amount_paise,currency,'pending',$3 FROM registrations WHERE id=$1",[m.registrationId,m.utrNumber,blob.url]);await pool.query("UPDATE registrations SET status='payment_pending',updated_at=NOW() WHERE id=$1",[m.registrationId]);await audit({id:m.userId},"payment.proof_submitted","registration",m.registrationId,{proofId:r.rows[0].id,utrNumber:m.utrNumber})}})
  }
  if(path==="upload"&&req.method==="POST"){
   const u=await requireUser(req,res,["author","admin"]);if(!u)return;if(!process.env.BLOB_READ_WRITE_TOKEN)return json(res,503,{error:"Paper storage is not configured. Add BLOB_READ_WRITE_TOKEN in Vercel."});
   return await handleUpload({request:req,body:await readBody(req),onBeforeGenerateToken:async(pathname,clientPayload)=>{let m={};try{m=JSON.parse(clientPayload||"{}")}catch{}if(!uuid(m.submissionId))throw new Error("A valid submission ID is required.");const own=await pool.query("SELECT id FROM submissions WHERE id=$1 AND author_id=$2",[m.submissionId,u.id]);if(!own.rowCount&&u.role!=="admin")throw new Error("You cannot upload to this submission.");return {access:"private",allowedContentTypes:["application/pdf"],maximumSizeInBytes:15*1024*1024,addRandomSuffix:true,tokenPayload:JSON.stringify({submissionId:m.submissionId,userId:u.id})}},onUploadCompleted:async({blob,tokenPayload})=>{const m=JSON.parse(tokenPayload||"{}");const r=await pool.query("INSERT INTO submission_files(submission_id,uploaded_by,file_name,mime_type,file_size,storage_url,storage_key) VALUES($1,$2,$3,'application/pdf',$4,$5,$6) RETURNING id",[m.submissionId,m.userId,blob.pathname.split("/").pop(),blob.size,blob.url,blob.pathname]);await audit({id:m.userId},"paper.file_uploaded","submission",m.submissionId,{fileId:r.rows[0].id})}})
  }
  if(path==="submissions"&&req.method==="POST"){
   const u=await requireUser(req,res,["author","admin"]);if(!u)return;const b=await readBody(req),title=String(b.title||"").trim(),abstract=String(b.abstract||"").trim(),track=String(b.track||"").trim();
   if(title.length<8||abstract.length<100||!track)return json(res,400,{error:"Add a paper title, an abstract of at least 100 characters and select a conference track."});
   const keys=Array.isArray(b.keywords)?b.keywords.map(x=>String(x).trim()).filter(Boolean).slice(0,12):String(b.keywords||"").split(",").map(x=>x.trim()).filter(Boolean).slice(0,12);
   const r=await pool.query("INSERT INTO submissions(paper_code,author_id,title,abstract,keywords,track,paper_type,status,submitted_at) VALUES($1,$2,$3,$4,$5,$6,$7,'submitted',NOW()) RETURNING *",[makePaperCode(),u.id,title,abstract,keys,track,["full_paper","short_paper","poster"].includes(b.paperType)?b.paperType:"full_paper"]);
   await audit(u,"paper.submitted","submission",r.rows[0].id,{paperCode:r.rows[0].paper_code},req);return json(res,201,{submission:r.rows[0]})
  }
  if(path==="submissions"&&req.method==="GET"){
   const u=await requireUser(req,res,["author","reviewer","admin"]);if(!u)return;let q,params=[];
   if(u.role==="admin")q="SELECT s.*,u.full_name AS author_name,u.email AS author_email FROM submissions s JOIN users u ON u.id=s.author_id ORDER BY s.created_at DESC";
   else if(u.role==="author"){q="SELECT s.* FROM submissions s WHERE s.author_id=$1 ORDER BY s.created_at DESC";params=[u.id]}
   else{q="SELECT s.*,u.full_name AS author_name FROM submissions s JOIN reviewer_assignments a ON a.submission_id=s.id JOIN users u ON u.id=s.author_id WHERE a.reviewer_id=$1 ORDER BY s.created_at DESC";params=[u.id]}
   const r=await pool.query(q,params);return json(res,200,{submissions:r.rows})
  }
  if(path==="reviews"&&req.method==="POST"){
   const u=await requireUser(req,res,["reviewer"]);if(!u)return;const b=await readBody(req);if(!uuid(b.submissionId)||!["accept","minor_revision","major_revision","reject"].includes(b.recommendation)||String(b.commentsToAuthor||"").trim().length<20)return json(res,400,{error:"Complete the review recommendation and author comments."});
   const a=await pool.query("SELECT id FROM reviewer_assignments WHERE submission_id=$1 AND reviewer_id=$2 AND status IN ('assigned','accepted')",[b.submissionId,u.id]);if(!a.rowCount)return json(res,403,{error:"This paper is not assigned to you."});
   const r=await pool.query("INSERT INTO reviews(submission_id,reviewer_id,recommendation,originality_score,technical_score,clarity_score,significance_score,comments_to_author,confidential_comments) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(submission_id,reviewer_id) DO UPDATE SET recommendation=EXCLUDED.recommendation,originality_score=EXCLUDED.originality_score,technical_score=EXCLUDED.technical_score,clarity_score=EXCLUDED.clarity_score,significance_score=EXCLUDED.significance_score,comments_to_author=EXCLUDED.comments_to_author,confidential_comments=EXCLUDED.confidential_comments,submitted_at=NOW() RETURNING *",[b.submissionId,u.id,b.recommendation,b.originalityScore||null,b.technicalScore||null,b.clarityScore||null,b.significanceScore||null,String(b.commentsToAuthor).trim(),String(b.confidentialComments||"").trim()||null]);
   await pool.query("UPDATE reviewer_assignments SET status='completed' WHERE submission_id=$1 AND reviewer_id=$2",[b.submissionId,u.id]);await audit(u,"review.submitted","submission",b.submissionId,{},req);return json(res,201,{review:r.rows[0]})
  }
  if(path==="registrations"&&req.method==="POST"){
   const u=await requireUser(req,res,["author","admin"]);if(!u)return;const b=await readBody(req);if(!["student","research_scholar","faculty","industry","attendee"].includes(b.registrationType)||String(b.institution||"").trim().length<2||String(b.country||"").trim().length<2||String(b.phone||"").trim().length<7)return json(res,400,{error:"Complete all registration details."});
   const r=await pool.query("INSERT INTO registrations(user_id,registration_type,institution,country,phone,amount_paise,status) VALUES($1,$2,$3,$4,$5,$6,'pending') RETURNING *",[u.id,b.registrationType,String(b.institution).trim(),String(b.country).trim(),String(b.phone).trim(),0]);await audit(u,"registration.created","registration",r.rows[0].id,{},req);return json(res,201,{registration:r.rows[0],paymentConfigured:!!(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET)})
  }
  if(path==="payments/order"&&req.method==="POST"){
   const u=await requireUser(req,res,["author"]);if(!u)return;if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET)return json(res,503,{error:"Online payment is not configured. Registration has been saved; contact the conference team for payment instructions."});
   const b=await readBody(req),r=await pool.query("SELECT * FROM registrations WHERE id=$1 AND user_id=$2",[b.registrationId,u.id]);if(!r.rowCount)return json(res,404,{error:"Registration not found."});const reg=r.rows[0];if(reg.amount_paise<=0)return json(res,400,{error:"No payment amount is configured for this registration."});
   const auth=Buffer.from(process.env.RAZORPAY_KEY_ID+":"+process.env.RAZORPAY_KEY_SECRET).toString("base64");const response=await fetch("https://api.razorpay.com/v1/orders",{method:"POST",headers:{Authorization:"Basic "+auth,"Content-Type":"application/json"},body:JSON.stringify({amount:reg.amount_paise,currency:reg.currency,receipt:reg.id})});const order=await response.json();if(!response.ok)return json(res,502,{error:"Payment provider could not create an order."});
   await pool.query("INSERT INTO payments(registration_id,provider,provider_order_id,amount_paise,currency,status) VALUES($1,'razorpay',$2,$3,$4,'created')",[reg.id,order.id,reg.amount_paise,reg.currency]);return json(res,201,{order:{id:order.id,amount:order.amount,currency:order.currency},keyId:process.env.RAZORPAY_KEY_ID})
  }
  if(path==="payments/verify"&&req.method==="POST"){
   const u=await requireUser(req,res,["author"]);if(!u)return;const b=await readBody(req),payload=String(b.orderId||"")+"|"+String(b.paymentId||"");const expected=crypto.createHmac("sha256",process.env.RAZORPAY_KEY_SECRET||"").update(payload).digest("hex");const got=String(b.signature||"");
   if(!process.env.RAZORPAY_KEY_SECRET||got.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(got)))return json(res,400,{error:"Payment verification failed."});
   const r=await pool.query("UPDATE payments p SET provider_payment_id=$1,status='paid',verified_at=NOW() FROM registrations g WHERE p.registration_id=g.id AND p.provider_order_id=$2 AND g.user_id=$3 RETURNING p.registration_id",[b.paymentId,b.orderId,u.id]);if(!r.rows[0])return json(res,404,{error:"Payment order not found."});await pool.query("UPDATE registrations SET status='confirmed',updated_at=NOW() WHERE id=$1",[r.rows[0].registration_id]);return json(res,200,{ok:true,message:"Payment verified and registration confirmed."})
  }
  if(path==="dashboard"&&req.method==="GET"){
   const u=await requireUser(req,res,["author","reviewer","admin"]);if(!u)return;
   if(u.role==="admin"){const [s,p,g,v]=await Promise.all([pool.query("SELECT (SELECT COUNT(*) FROM users WHERE role='author')::int AS authors,(SELECT COUNT(*) FROM submissions)::int AS submissions,(SELECT COUNT(*) FROM submissions WHERE status='under_review')::int AS under_review,(SELECT COUNT(*) FROM submissions WHERE status='accepted')::int AS accepted,(SELECT COUNT(*) FROM registrations)::int AS registrations,(SELECT COUNT(*) FROM payments WHERE status='paid')::int AS paid_payments"),pool.query("SELECT s.*,u.full_name AS author_name,u.email AS author_email FROM submissions s JOIN users u ON u.id=s.author_id ORDER BY s.created_at DESC LIMIT 100"),pool.query("SELECT r.*,u.full_name,u.email FROM registrations r JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC LIMIT 100"),pool.query("SELECT id,full_name,email FROM users WHERE role='reviewer' AND is_active=TRUE ORDER BY full_name")]);return json(res,200,{role:u.role,stats:s.rows[0],submissions:p.rows,registrations:g.rows,reviewers:v.rows})}
   if(u.role==="reviewer"){const r=await pool.query("SELECT s.*,a.status AS assignment_status,a.due_at,(SELECT json_agg(json_build_object('id',f.id,'file_name',f.file_name) ORDER BY f.created_at DESC) FROM submission_files f WHERE f.submission_id=s.id) AS files FROM submissions s JOIN reviewer_assignments a ON a.submission_id=s.id WHERE a.reviewer_id=$1 ORDER BY s.created_at DESC",[u.id]);return json(res,200,{role:u.role,submissions:r.rows})}
   const [s,g]=await Promise.all([pool.query("SELECT s.*,(SELECT json_agg(json_build_object('file_name',f.file_name,'storage_url',f.storage_url,'created_at',f.created_at) ORDER BY f.created_at DESC) FROM submission_files f WHERE f.submission_id=s.id) AS files FROM submissions s WHERE s.author_id=$1 ORDER BY s.created_at DESC",[u.id]),pool.query("SELECT * FROM registrations WHERE user_id=$1 ORDER BY created_at DESC",[u.id])]);return json(res,200,{role:u.role,submissions:s.rows,registrations:g.rows})
  }
  if(path==="admin/users"&&req.method==="GET"){const u=await requireUser(req,res,["admin"]);if(!u)return;const r=await pool.query("SELECT id,full_name,email,role,affiliation,is_active,created_at FROM users ORDER BY created_at DESC");return json(res,200,{users:r.rows})}
  if(path==="admin/users"&&req.method==="POST"){
   const a=await requireUser(req,res,["admin"]);if(!a)return;const b=await readBody(req),mail=email(b.email),name=String(b.fullName||"").trim(),pw=String(b.password||"");if(!validEmail(mail)||name.length<2||pw.length<12||!["reviewer","admin"].includes(b.role))return json(res,400,{error:"Provide valid name, email, 12+ character password and reviewer/admin role."});
   const hash=await bcrypt.hash(pw,12),r=await pool.query("INSERT INTO users(full_name,email,password_hash,role,affiliation) VALUES($1,$2,$3,$4,$5) RETURNING id,full_name,email,role,affiliation,is_active",[name,mail,hash,b.role,String(b.affiliation||"").trim()||null]);await audit(a,"user.created","user",r.rows[0].id,{role:b.role},req);return json(res,201,{user:r.rows[0]})
  }
  if(path==="admin/assign"&&req.method==="POST"){
   const a=await requireUser(req,res,["admin"]);if(!a)return;const b=await readBody(req);if(!uuid(b.submissionId)||!uuid(b.reviewerId))return json(res,400,{error:"Select a paper and reviewer."});const v=await pool.query("SELECT id FROM users WHERE id=$1 AND role='reviewer' AND is_active=TRUE",[b.reviewerId]);if(!v.rowCount)return json(res,404,{error:"Reviewer not found."});
   const r=await pool.query("INSERT INTO reviewer_assignments(submission_id,reviewer_id,assigned_by,due_at) VALUES($1,$2,$3,$4) ON CONFLICT(submission_id,reviewer_id) DO UPDATE SET status='assigned',assigned_by=EXCLUDED.assigned_by,due_at=EXCLUDED.due_at RETURNING *",[b.submissionId,b.reviewerId,a.id,b.dueAt||null]);await pool.query("UPDATE submissions SET status='under_review',updated_at=NOW() WHERE id=$1 AND status='submitted'",[b.submissionId]);await audit(a,"reviewer.assigned","submission",b.submissionId,{reviewerId:b.reviewerId},req);return json(res,201,{assignment:r.rows[0]})
  }
  if(path==="admin/submission-status"&&req.method==="POST"){
   const a=await requireUser(req,res,["admin"]);if(!a)return;const b=await readBody(req),allowed=["submitted","under_review","revision_required","accepted","rejected","withdrawn"];if(!uuid(b.submissionId)||!allowed.includes(b.status))return json(res,400,{error:"Invalid submission status."});const r=await pool.query("UPDATE submissions SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,paper_code,status",[b.status,b.submissionId]);if(!r.rows[0])return json(res,404,{error:"Submission not found."});await audit(a,"submission.status_changed","submission",b.submissionId,{status:b.status},req);return json(res,200,{submission:r.rows[0]})
  }
  if(path==="admin/announcements"&&req.method==="POST"){
   const a=await requireUser(req,res,["admin"]);if(!a)return;const b=await readBody(req),title=String(b.title||"").trim(),body=String(b.body||"").trim();if(title.length<3||body.length<5)return json(res,400,{error:"Enter an announcement title and message."});const r=await pool.query("INSERT INTO announcements(title,body,is_published,published_at,created_by) VALUES($1,$2,$3,CASE WHEN $3 THEN NOW() ELSE NULL END,$4) RETURNING *",[title,body,!!b.publish,a.id]);return json(res,201,{announcement:r.rows[0]})
  }
  if(path==="admin/audit"&&req.method==="GET"){const a=await requireUser(req,res,["admin"]);if(!a)return;const r=await pool.query("SELECT l.*,u.full_name,u.email FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.created_at DESC LIMIT 200");return json(res,200,{logs:r.rows})}

  if(path==="certificates"&&req.method==="GET"){
   const u=await requireUser(req,res,["author","admin"]);if(!u)return;
   const r=u.role==="admin"
    ?await pool.query("SELECT c.*,u.full_name,u.email FROM certificates c JOIN users u ON u.id=c.user_id ORDER BY c.issued_at DESC")
    :await pool.query("SELECT c.*,u.full_name,u.email FROM certificates c JOIN users u ON u.id=c.user_id WHERE c.user_id=$1 ORDER BY c.issued_at DESC",[u.id]);
   return json(res,200,{certificates:r.rows});
  }
  if(path==="admin/certificates"&&req.method==="POST"){
   const a=await requireUser(req,res,["admin"]);if(!a)return;const b=await readBody(req);
   if(!uuid(b.registrationId)||!["participation","paper_presentation","reviewer"].includes(b.certificateType))return json(res,400,{error:"Select a valid registration and certificate type."});
   const reg=await pool.query("SELECT id,user_id FROM registrations WHERE id=$1",[b.registrationId]);if(!reg.rowCount)return json(res,404,{error:"Registration not found."});
   const code="ICMRIS27-CERT-"+crypto.randomBytes(5).toString("hex").toUpperCase();
   const r=await pool.query("INSERT INTO certificates(user_id,registration_id,certificate_type,certificate_code,issued_by) VALUES($1,$2,$3,$4,$5) RETURNING *",[reg.rows[0].user_id,reg.rows[0].id,b.certificateType,code,a.id]);
   await audit(a,"certificate.issued","certificate",r.rows[0].id,{certificateCode:code},req);return json(res,201,{certificate:r.rows[0]});
  }
  return json(res,404,{error:"API route not found."});
 }catch(e){console.error("ICMRIS API error:",e.message);const s=e.status||(e.code==="23505"?409:500);return json(res,s,{error:s===409?"This record already exists.":s===400?e.message:"The server could not complete this request."})}
};