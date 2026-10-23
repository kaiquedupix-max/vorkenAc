// Local preview with an isolated Postgres engine. Never uses production customers or credentials.
import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { initVorkenPlatform,installVorkenPlatform } from './vorkenPlatform.js';
import { hash,seal } from './vorkenDomain.js';
const db=new PGlite();
const pool={query:async(sql,args)=>{
  if(sql.includes('pg_advisory_'))return {rows:[]};
  if(!args&&sql.includes('CREATE TABLE')){await db.exec(sql);return {rows:[]};}return db.query(sql,args);
},connect:async()=>({...pool,release(){}})};
await db.exec(`CREATE TABLE analyses(id BIGSERIAL PRIMARY KEY,public_token TEXT,label TEXT,status TEXT DEFAULT 'waiting',expires_at TIMESTAMPTZ,
 processing_stage TEXT DEFAULT 'waiting',external_source TEXT,external_player_id TEXT,external_discord_user_id TEXT,external_verification_code TEXT,external_ticket_channel_id TEXT,
 external_decision TEXT,external_decision_at TIMESTAMPTZ,external_decision_result TEXT);
 CREATE TABLE scan_findings(id BIGSERIAL PRIMARY KEY,analysis_id BIGINT,title TEXT,severity TEXT,artifact_type TEXT,artifact_value TEXT,evidence JSONB);`);
await initVorkenPlatform(pool);
process.env.SESSION_SECRET=crypto.randomBytes(32).toString('hex');
const fetchOriginal=globalThis.fetch;
globalThis.fetch=(url,options)=>String(url).startsWith('https://discord.com/api/')?Promise.resolve(Response.json([{id:'123456789012345678',name:'Comunidade de demonstração',owner:true}])):fetchOriginal(url,options);
const customerId=crypto.randomUUID(),serverId=crypto.randomUUID();
await pool.query("INSERT INTO vorken_customers(id,discord_id,name) VALUES($1,'123456789012345678','Cliente de demonstração')",[customerId]);
await pool.query("INSERT INTO vorken_licenses(customer_id,plan_id,status,expires_at) VALUES($1,'mensal','active',NOW()+interval '1 month')",[customerId]);
await pool.query("INSERT INTO vorken_logins(token_hash,customer_id,access_token,expires_at) VALUES($1,$2,$3,NOW()+interval '1 hour')",[hash(customerId),customerId,seal('preview-only',process.env.SESSION_SECRET)]);
await pool.query("INSERT INTO vorken_guilds(id,customer_id,name) VALUES('123456789012345678',$1,'Demonstração')",[customerId]);
await pool.query("INSERT INTO vorken_servers(id,customer_id,guild_id,name,discord_invite,token_hash,slug) VALUES($1,$2,'123456789012345678','Servidor de demonstração','https://discord.gg/demo',$3,'demo')",[serverId,customerId,hash('preview-only')]);
const app=express(),dirname=path.dirname(fileURLToPath(import.meta.url));
app.use(express.json());app.use(cookieParser());
installVorkenPlatform(app,{pool,publicUrl:'http://localhost:4317',requireAdmin:(req,res,next)=>req.cookies.preview_admin==='yes'?next():res.status(401).json({message:'Prévia: entre por /preview/owner.'}),
 learnAnalysisArtifacts:async()=>{},revokeLearnedTrustForFindings:async()=>{}});
app.get('/preview/customer',(_req,res)=>{res.cookie('vorken_customer',customerId,{httpOnly:true,sameSite:'lax'});res.redirect('/servidor');});
app.get('/preview/owner',(_req,res)=>{res.cookie('preview_admin','yes',{httpOnly:true,sameSite:'lax'});res.redirect('/admin/clientes');});
app.get('/servidor',(_req,res)=>res.sendFile(path.join(dirname,'public','servidor.html')));
app.get('/admin/clientes',(_req,res)=>res.sendFile(path.join(dirname,'public','clientes.html')));
app.use(express.static(path.join(dirname,'public')));
app.listen(4317,'127.0.0.1',()=>console.log('Prévia isolada: http://localhost:4317/servidor'));
