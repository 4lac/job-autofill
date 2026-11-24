#!/usr/bin/env python3
"""
job-autofill by Reyof (@4lavc): fills job application forms from your own saved data.
Single file: local web UI (Flask) + the form filler (Playwright), nothing else.

  python job_autofill.py            -> opens the UI at http://127.0.0.1:5055
  python job_autofill.py --worker   -> internal: the browser process the UI starts

Privacy: everything runs on your computer. The tool never submits an application.
"""
import argparse
import atexit
import getpass
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, request, send_from_directory

BASE = Path(__file__).resolve().parent


def _data_dir():
    """Your personal data lives OUTSIDE the tool folder, so sending someone the tool never sends your data."""
    env = os.environ.get("JOB_AUTOFILL_DATA")
    if env:
        return Path(env)
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return root / "job-autofill"


DATA_DIR = _data_dir()
SESSION_DIR = DATA_DIR / ".browser_profile"
CHROME_SESSION_DIR = DATA_DIR / ".browser_profile_chrome"
SCAN_DIR = DATA_DIR / "scan_reports"
FILES = DATA_DIR / "my_files"
PROFILE = DATA_DIR / "profile.json"
EXAMPLE = BASE / "profile.example.json"
DEVICE_MARK = DATA_DIR / ".device"
PERSONAL = [PROFILE, FILES, SESSION_DIR, CHROME_SESSION_DIR, SCAN_DIR]
LEGACY = [BASE / "profile.json", BASE / "my_files", BASE / ".browser_profile",
          BASE / ".browser_profile_chrome", BASE / "scan_reports"]  # where old versions kept your data
PORT = 5055
ORIGINS = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
KINDS = {"cv": "cv", "photo": "photo", "id_copy": "id_copy", "national_address": "national_address",
         "ielts": "ielts", "toefl": "toefl", "step": "step", "qiyas": "qiyas"}
EXTS = {".pdf", ".png", ".jpg", ".jpeg", ".webp"}
# On Windows, keep the browser sandbox ON (removes the "--no-sandbox" warning banner)
SANDBOX = sys.platform == "win32"

# ======================================================================
#  The web page (UI)
# ======================================================================
UI_HTML = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>مساعد التقديم على الوظائف</title>
<style>
:root{--bg:#f4f7fb;--card:#fff;--ink:#1c2733;--mute:#6b7a8a;--line:#d9e2ec;--main:#2f6fed;--main2:#1f55c4;--ok:#1a8f4c;--warn:#b26a00}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:"Segoe UI",Tahoma,system-ui,sans-serif;line-height:1.6}
.wrap{max-width:900px;margin:0 auto;padding:20px 16px 120px}
h1{font-size:24px;margin:8px 0 4px}
.sub{color:var(--mute);margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0}
.card h2{font-size:17px;margin:0 0 12px;display:flex;gap:8px;align-items:center}
.num{background:var(--main);color:#fff;border-radius:50%;width:26px;height:26px;display:inline-grid;place-items:center;font-size:14px}
.note{background:#eef4ff;border:1px solid #cfe0ff;border-radius:10px;padding:10px 12px;font-size:14px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
label{display:block;font-size:13px;color:var(--mute);margin-bottom:3px}
input[type=text],input[type=date],select,textarea{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;background:#fff;color:var(--ink)}
input:focus,select:focus,textarea:focus{outline:2px solid #b9d0ff;border-color:var(--main)}
.ltr{direction:ltr;text-align:left}
.bi{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.btn{border:0;border-radius:10px;padding:10px 16px;font:inherit;cursor:pointer;background:#e8eef7;color:var(--ink)}
.btn.main{background:var(--main);color:#fff}.btn.main:hover{background:var(--main2)}
.btn.small{padding:5px 10px;font-size:13px}
.btn.danger{background:#fdeaea;color:#a12626}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.slot{border:1px dashed var(--line);border-radius:10px;padding:10px;display:flex;flex-direction:column;gap:6px}
.slot .name{font-size:13px;color:var(--ok);word-break:break-all}.slot .name.empty{color:var(--mute)}
.slot img{max-width:90px;max-height:90px;border-radius:8px;border:1px solid var(--line)}
.cert{display:grid;grid-template-columns:1fr auto auto;gap:8px;align-items:end;margin-bottom:8px}
.test{display:grid;grid-template-columns:90px 1fr 1fr 1.4fr;gap:8px;align-items:end;margin-bottom:8px}
.test b{padding-bottom:9px}
@media(max-width:640px){.test{grid-template-columns:1fr 1fr}.test b{grid-column:1/-1;padding:0}.bi{grid-template-columns:1fr}}
.bar{position:fixed;bottom:0;left:0;right:0;background:#fff;border-top:1px solid var(--line);padding:10px 16px;display:flex;justify-content:center;gap:10px}
#log{background:#0f1720;color:#d7e3f1;border-radius:10px;padding:10px;font:13px/1.5 Consolas,monospace;height:190px;overflow:auto;white-space:pre-wrap;direction:ltr;text-align:left;margin-top:10px}
#toast{position:fixed;top:14px;left:50%;transform:translateX(-50%);background:#1c2733;color:#fff;padding:9px 16px;border-radius:10px;opacity:0;transition:.25s;pointer-events:none;z-index:5}
#toast.on{opacity:1}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
.by{display:flex;flex-direction:column;align-items:flex-end;text-decoration:none;color:var(--ink);background:#fff;border:1px solid var(--line);border-radius:12px;padding:6px 14px;line-height:1.35}
.by b{font-size:15px}.by span{color:var(--main);font-size:13px;direction:ltr}
.foot{text-align:center;color:var(--mute);font-size:13px;margin-top:24px}.foot a{color:var(--main);text-decoration:none}
.picker{direction:ltr;text-align:left;border:1px solid var(--line);border-radius:10px;padding:12px;margin-top:12px;background:#fafcff}
.picker small{display:block;color:var(--mute);margin-top:8px}
.chk{display:inline-flex;gap:6px;align-items:center;font-size:14px;color:var(--ink);margin:0}
</style>
</head>
<body>
<div class="wrap">
  <div class="note" id="bad" style="display:none;background:#fdeaea;border-color:#f3b8b8">⚠️ الصفحة مفتوحة بطريقة غلط، ولن يشتغل الحفظ. شغّل <b>start.bat</b> (أو <code>python app.py</code>) وافتح <b dir="ltr">http://127.0.0.1:5055</b> في المتصفح.</div>
  <div class="top">
    <div><h1>مساعد التقديم على الوظائف</h1>
    <p class="sub">عبّ بياناتك مرة وحدة، والأداة تعبي لك صفحات التقديم. كل شي اختياري، والحقل الفاضي يتجاهله.</p></div>
    <a class="by" href="https://x.com/4lavc" target="_blank" rel="noopener"><b>Reyof</b><span>@4lavc</span></a>
  </div>
  <div class="note">🔒 بياناتك وملفاتك تنحفظ على جهازك فقط، في مجلد خاص بحسابك خارج مجلد الأداة: <span id="ddir" dir="ltr"></span>. فلو أرسلت الأداة لأحد، ما ينرسل معها شي من بياناتك.</div>
  <div id="alerts"></div>

  <div class="card"><h2><span class="num">١</span> عبّ بياناتك</h2><div id="form"></div></div>

  <div class="card"><h2>🌐 اختبارات اللغة</h2><div id="tests"></div></div>

  <div class="card"><h2>📎 الملفات</h2>
    <div class="grid" id="slots"></div>
    <h2 style="margin-top:18px">🎓 الشهادات المهنية</h2>
    <div id="certs"></div>
    <button class="btn small" onclick="addCert()">+ أضف شهادة</button>
  </div>

  <div class="card"><h2><span class="num">٢</span> شغّل التعبئة</h2>
    <div class="note">١) اضغط «افتح المتصفح». ٢) افتح صفحة التقديم فيه. ٣) في القائمة الإنجليزية اختر الصفحة اللي تبي تعبيها واضغط Fill. كرر مع كل مرحلة. الأداة ما ترسل الطلب أبداً، المراجعة والإرسال عليك.</div>
    <label>رابط صفحة التقديم (اختياري، يفتحه المتصفح مباشرة)</label>
    <input type="text" id="url" class="ltr" placeholder="https://...">
    <div class="row" style="margin-top:10px">
      <button class="btn main" onclick="afStart()">١ افتح المتصفح</button>
      <button class="btn danger" onclick="afStop()">إيقاف</button>
      <label class="chk"><input type="checkbox" id="dry"> تجربة فقط (بدون تعبئة فعلية)</label>
      <label class="chk"><input type="checkbox" id="chrome"> استخدم كروم اللي عندي</label>
    </div>
    <div class="picker">
      <label>Select the page to fill</label>
      <select id="pg" onchange="selUrl=(PAGES.find(p=>p.i==this.value)||{}).url||''"><option value="">Open the browser first</option></select>
      <div class="row" style="margin-top:8px">
        <button class="btn small" onclick="refreshPages()">⟳ Refresh pages</button>
        <button class="btn main" onclick="afFill()">Fill selected page</button>
        <button class="btn small" onclick="afScan()">🔍 Scan page (report)</button>
      </div>
      <small>Open the application page in the browser window, click Refresh, pick it from the list, then click Fill. Use Scan to get a report of every field on the page without filling anything.</small>
    </div>
    <div class="row" style="margin-top:10px"><button class="btn small" onclick="copyLog()">📋 نسخ السجل</button><span class="muted" style="font-size:12px;margin-inline-start:8px">بياناتك الشخصية تنخفي من السجل تلقائياً</span></div>
    <div id="log"></div>
  </div>
  <p class="foot"><button class="btn small danger" onclick="wipeAll()">🗑️ حذف كل بياناتي من هذا الجهاز</button><br>job-autofill · by Reyof · <a href="https://x.com/4lavc" target="_blank" rel="noopener" dir="ltr">@4lavc</a></p>
</div>

<div class="bar"><button class="btn main" onclick="save()">💾 حفظ البيانات</button></div>
<div id="toast"></div>

<script>
const GENDER=[["أنثى",["Female","أنثى"]],["ذكر",["Male","ذكر"]]];
const NAT=[["سعودي / سعودية",["Saudi","Saudi Arabia","سعودي","سعودية","السعودية"]]];
const COUNTRY=[["السعودية",["Saudi Arabia","السعودية"]]];
const DEGREE=[["ثانوية",["High School","الثانوية","ثانوي"]],["دبلوم",["Diploma","دبلوم"]],["بكالوريوس",["Bachelor","بكالوريوس"]],["ماجستير",["Master","ماجستير"]],["دكتوراه",["PhD","Doctorate","دكتوراه"]]];
const SECTIONS=[
 ["المعلومات الشخصية",[
  ["first_name","الاسم الأول","bi"],["second_name","اسم الأب (الاسم الثاني)","bi"],["third_name","اسم الجد (الاسم الثالث)","bi"],["last_name","اسم العائلة","bi"],["full_name","الاسم الكامل","bi"],
  ["email","الإيميل","text",1],["phone","الجوال","text",1],["national_id","رقم الهوية","text",1],["dob","تاريخ الميلاد (ميلادي)","date"],
  ["gender","الجنس","choice",GENDER],["nationality","الجنسية","choice",NAT],["country","الدولة","choice",COUNTRY]]],
 ["العنوان الوطني",[
  ["region","المنطقة","text"],["city","المدينة","text"],["district","الحي","text"],["street","الشارع","text"],
  ["building_number","رقم المبنى","text",1],["additional_number","الرقم الإضافي","text",1],["postal_code","الرمز البريدي","text",1],["short_address","العنوان المختصر","text",1]]],
 ["التعليم",[
  ["university","الجامعة","text"],["degree","المؤهل","choice",DEGREE],["major","التخصص","text"],["graduation_year","سنة التخرج","text",1],["gpa","المعدل","text",1]]],
 ["الخبرة",[
  ["job_title","المسمى الوظيفي","text"],["company","الشركة","text"],["years_experience","سنوات الخبرة","text",1],["expected_salary","الراتب المتوقع","text",1],["notice_period","فترة الإشعار","text"]]],
 ["الروابط وحسابات التواصل الاجتماعي",[
  ["linkedin","لينكد إن","text",1],["github","GitHub","text",1],["website","موقع شخصي","text",1],
  ["twitter","X (تويتر)","text",1],["instagram","انستغرام","text",1],["snapchat","سناب شات","text",1],
  ["tiktok","تيك توك","text",1],["facebook","فيسبوك","text",1],["youtube","يوتيوب","text",1],["telegram","تيليجرام","text",1]]],
 ["خطاب التقديم الجاهز",[["cover_letter","نص الخطاب","area"]]]
];
const TESTS=[["ielts","IELTS"],["toefl","TOEFL"],["step","STEP"],["qiyas","قياس"]];
const SLOTS=[["cv","السيرة الذاتية (PDF أو Word)","cv_path"],["photo","الصورة الشخصية","photo_path"],["id_copy","صورة بطاقة الهوية","id_copy_path"],["national_address","وثيقة العنوان الوطني","national_address_path"]];
let P={},PAGES=[],selUrl="";

const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function toast(m){const t=$("#toast");t.textContent=m;t.classList.add("on");setTimeout(()=>t.classList.remove("on"),2200)}
const NOCONN="ما قدرت أتصل بالأداة. تأكد إن نافذة التشغيل (start.bat) شغالة، وإن الصفحة مفتوحة من العنوان http://127.0.0.1:5055 وليس بدبل كليك على الملف.";
async function api(url,opt){let r;try{r=await fetch(url,opt)}catch(e){throw new Error(NOCONN)}
 const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||("صار خطأ ("+r.status+")"));return j}
const post=(u,b)=>api(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});

function textInput(k,ltr,ph){return `<input type="text" data-k="${k}" class="${ltr?"ltr":""}" placeholder="${ph||""}">`}
function field(f){
 const [k,l,t,x]=f;let h=`<div><label>${l}</label>`;
 if(t==="bi")h+=`<div class="bi">${textInput(k+"_ar",0,"عربي")}${textInput(k+"_en",1,"English")}</div>`;
 else if(t==="text")h+=textInput(k,x);
 else if(t==="date")h+=`<input type="date" data-k="${k}">`;
 else if(t==="area")h+=`<textarea rows="5" data-k="${k}"></textarea>`;
 else if(t==="choice")h+=`<select data-c="${k}"><option value="">—</option>${x.map((o,i)=>`<option value="${i}">${o[0]}</option>`).join("")}<option value="other">أخرى…</option></select><input type="text" data-co="${k}" style="display:none;margin-top:6px" placeholder="اكتبها هنا">`;
 return h+"</div>";
}
function render(){
 $("#form").innerHTML=SECTIONS.map(([t,fs])=>`<h3 style="margin:18px 0 8px;font-size:15px">${t}</h3><div class="grid">${fs.map(field).join("")}</div>`).join("");
 document.querySelectorAll("[data-k]").forEach(e=>{e.value=P[e.dataset.k]??"";e.oninput=()=>{P[e.dataset.k]=e.value}});
 for(const [,fs] of SECTIONS)for(const f of fs)if(f[2]==="choice")bindChoice(f[0],f[3]);
 $("#tests").innerHTML=TESTS.map(([t,n])=>`<div class="test"><b>${n}</b>
  <div><label>الدرجة</label><input type="text" class="ltr" data-k="${t}_score"></div>
  <div><label>التاريخ</label><input type="date" data-k="${t}_date"></div>
  <div><label>ملف النتيجة</label><div class="row"><span class="name" id="n_${t}"></span><input type="file" id="f_${t}" accept=".pdf,.png,.jpg,.jpeg,.webp" style="max-width:170px"></div></div></div>`).join("");
 document.querySelectorAll("#tests [data-k]").forEach(e=>{e.value=P[e.dataset.k]??"";e.oninput=()=>{P[e.dataset.k]=e.value}});
 TESTS.forEach(([t])=>{showName("n_"+t,P[t+"_path"]);$("#f_"+t).onchange=ev=>up(t,t+"_path",ev.target.files[0],"n_"+t)});
 $("#slots").innerHTML=SLOTS.map(([kind,l,key])=>`<div class="slot"><b style="font-size:14px">${l}</b>${kind==="photo"?'<img id="pv" style="display:none">':""}
  <span class="name empty" id="n_${kind}"></span>
  <input type="file" id="f_${kind}" accept="${kind==="cv"?".pdf,.docx,":""}.png,.jpg,.jpeg,.webp${kind==="cv"?"":",.pdf"}">
  <button class="btn small danger" onclick="rm('${key}','n_${kind}')">حذف</button></div>`).join("");
 SLOTS.forEach(([kind,,key])=>{showName("n_"+kind,P[key]);$("#f_"+kind).onchange=ev=>up(kind,key,ev.target.files[0],"n_"+kind)});
 preview();renderCerts();
}
function bindChoice(k,opts){
 const s=document.querySelector(`[data-c="${k}"]`),o=document.querySelector(`[data-co="${k}"]`);
 const cur=P[k],first=Array.isArray(cur)?cur[0]:cur;
 if(first){const i=opts.findIndex(x=>x[1][0]===first);if(i>=0)s.value=i;else{s.value="other";o.style.display="";o.value=Array.isArray(cur)?cur[0]:cur}}
 const upd=()=>{if(s.value===""){P[k]="";o.style.display="none"}
  else if(s.value==="other"){o.style.display="";P[k]=o.value?[o.value]:""}
  else{o.style.display="none";P[k]=opts[+s.value][1]}};
 s.onchange=upd;o.oninput=upd;
}
function showName(id,path){const e=$("#"+id);if(!e)return;e.textContent=path?"✓ "+path.split("/").pop():"ما انرفع شي";e.className="name"+(path?"":" empty")}
function preview(){const p=P.photo_path,im=$("#pv");if(!im)return;if(p){im.src="/files/"+p.replace(/^my_files\//,"")+"?t="+Date.now();im.style.display=""}else im.style.display="none"}
async function up(kind,key,file,nameId,extra){
 if(!file)return;const fd=new FormData();fd.append("kind",kind);fd.append("file",file);if(extra)fd.append("name",extra);
 try{const r=await api("/api/upload",{method:"POST",body:fd});P[key]=r.path;showName(nameId,r.path);if(key==="photo_path")preview();await autosave();toast("انرفع وانحفظ ✓");return r.path}
 catch(e){toast(e.message)}
}
async function rm(key,nameId){const p=P[key];if(p)await post("/api/delete",{path:p});P[key]="";showName(nameId,"");preview();await autosave()}
function renderCerts(){
 P.certificates=P.certificates||[];
 $("#certs").innerHTML=P.certificates.map((c,i)=>`<div class="cert"><div><label>اسم الشهادة</label><input type="text" value="${esc(c.name)}" oninput="P.certificates[${i}].name=this.value"></div>
  <div><label>الملف</label><div class="row"><span class="name ${c.path?"":"empty"}">${c.path?"✓ "+esc(c.path.split("/").pop()):"ما انرفع شي"}</span><input type="file" accept=".pdf,.png,.jpg,.jpeg,.webp" style="max-width:150px" onchange="upCert(${i},this.files[0])"></div></div>
  <button class="btn small danger" onclick="delCert(${i})">حذف</button></div>`).join("");
}
function addCert(){P.certificates.push({name:"",path:""});renderCerts()}
async function upCert(i,f){const p=await up("certificate","_tmp",f,"_none",P.certificates[i].name);if(p){P.certificates[i].path=p;delete P._tmp;renderCerts();await autosave()}}
async function delCert(i){const c=P.certificates[i];if(c.path)await post("/api/delete",{path:c.path});P.certificates.splice(i,1);renderCerts();await autosave()}
async function autosave(){try{await post("/api/profile",P)}catch(e){}}
async function save(){try{await post("/api/profile",P);toast("تم الحفظ ✓")}catch(e){toast(e.message)}}

let since=0,timer=null;
function poll(){clearInterval(timer);timer=setInterval(async()=>{try{const r=await api("/api/autofill/status?since="+since);since=r.next;
 if(r.lines.length){const L=$("#log");L.textContent+=r.lines.filter(x=>!x.includes("[Enter]")&&!x.startsWith("[PAGES]")).join("\n")+"\n";L.scrollTop=L.scrollHeight;if(r.lines.some(x=>x.startsWith("[READY]")||x.startsWith("[OPENED]")))refreshPages()}
 if(!r.running)clearInterval(timer)}catch(e){}},1000)}
async function afStart(){try{await save();toast("جاري فتح المتصفح…");const r=await post("/api/autofill/start",{dry:$("#dry").checked,chrome:$("#chrome").checked,url:$("#url").value});
 if(r.new_process){$("#log").textContent="";since=0}poll();setTimeout(refreshPages,2500);toast(r.new_process?"انفتح المتصفح ✓":"انفتحت صفحة جديدة ✓")}catch(e){toast(e.message)}}
async function refreshPages(){
 try{const r=await api("/api/autofill/pages");PAGES=r.pages||[];const s=$("#pg");
  s.innerHTML=PAGES.length?PAGES.map(p=>`<option value="${p.i}">${p.i+1}. ${esc((p.title||"(untitled)").slice(0,50))} — ${esc(p.url.slice(0,60))}</option>`).join(""):'<option value="">No pages yet. Open the browser first</option>';
  const keep=PAGES.find(p=>p.url===selUrl);if(keep)s.value=keep.i;else if(PAGES.length){s.value=PAGES[PAGES.length-1].i;selUrl=PAGES[PAGES.length-1].url}}
 catch(e){toast(e.message)}}
async function afFill(){const v=$("#pg").value;if(v===""){toast("Select a page first");return}
 try{await post("/api/autofill/fill",{index:+v});poll();setTimeout(refreshPages,2500)}catch(e){toast(e.message)}}
async function afScan(){const v=$("#pg").value;if(v===""){toast("Select a page first");return}
 try{await post("/api/autofill/scan",{index:+v});poll()}catch(e){toast(e.message)}}
function copyLog(){navigator.clipboard.writeText($("#log").textContent).then(()=>toast("Copied ✓"))}
async function afStop(){await post("/api/autofill/stop",{});toast("تم الإيقاف")}

if(location.protocol==="file:")$("#bad").style.display="";
async function wipeAll(){
 if(!confirm("بتنحذف كل بياناتك وملفاتك وجلسات المتصفح من هذا الجهاز نهائياً. متأكد؟"))return;
 try{await post("/api/wipe",{});P=await api("/api/profile");render();toast("انحذفت كل البيانات ✓")}catch(e){toast(e.message)}}
async function legacyDo(a){try{await post("/api/legacy",{action:a});P=await api("/api/profile");render();$("#alerts").innerHTML="";toast(a==="migrate"?"انتقلت بياناتك لمكان آمن ✓":"انحذفت ✓")}catch(e){toast(e.message)}}
async function startup(){
 try{const i=await api("/api/info");$("#ddir").textContent=i.data_dir;let h="";
  if(i.wiped)h+='<div class="note">⚠️ هذي الأداة اشتغلت على جهاز أو حساب مختلف، فنُظّفت أي بيانات قديمة كانت معها. عبّ بياناتك من جديد.</div>';
  if(i.legacy)h+='<div class="note">وجدت بيانات داخل مجلد الأداة نفسه (نسخة قديمة). هل هي بياناتك أنت؟<br><button class="btn small main" onclick="legacyDo(\'migrate\')">نعم، انقلها لمكان آمن</button> <button class="btn small danger" onclick="legacyDo(\'delete\')">لا، احذفها</button></div>';
  $("#alerts").innerHTML=h}catch(e){}}
(async()=>{try{P=await api("/api/profile")}catch(e){toast(e.message)}render();startup()})();
</script>
</body>
</html>
'''

# ======================================================================
#  Part 1: the form filler (runs inside the browser process)
# ======================================================================
# مفتاح البيانات -> كلمات يدور عليها في اسم الحقل (عربي وانجليزي)
KEYWORDS = {
    "first_name": ["first name", "given name", "firstname", "الاسم الأول", "اسم الأول"],
    "second_name": ["second name", "middle name", "father name", "fathers name", "الاسم الثاني", "الاسم الأوسط", "اسم الأب"],
    "third_name": ["third name", "grandfather name", "grandfathers name", "grandfather", "الاسم الثالث", "اسم الجد"],
    "last_name": ["last name", "family name", "surname", "lastname", "اسم العائلة", "الاسم الأخير"],
    "full_name": ["full name", "your name", "name", "الاسم الكامل", "الاسم", "اسم"],
    "email": ["email", "email address", "e-mail", "البريد الإلكتروني", "عنوان البريد الإلكتروني", "ايميل"],
    "phone_device_type": ["phone device type", "phone type", "device type", "نوع الهاتف", "نوع الجوال"],
    "phone_country_code": ["country phone code", "phone country code", "phone code", "country code", "dial code",
                           "رمز الدولة", "مفتاح الدولة"],
    "phone": ["phone", "mobile", "telephone", "contact number", "رقم الجوال", "الجوال", "جوال", "الهاتف", "هاتف"],
    "national_id": ["national id", "id number", "iqama", "identity", "رقم الهوية", "الهوية الوطنية", "الهوية"],
    "dob": ["date of birth", "birth date", "birthdate", "dob", "birthday", "تاريخ الميلاد", "الميلاد"],
    "gender": ["gender", "sex", "الجنس"],
    "nationality": ["nationality", "الجنسية"],
    "country": ["country", "الدولة", "البلد"],
    "region": ["region", "province", "state", "المنطقة"],
    "city": ["city", "town", "المدينة"],
    "district": ["district", "neighborhood", "neighbourhood", "الحي"],
    "street": ["street", "address", "الشارع", "العنوان"],
    "building_number": ["building number", "building no", "رقم المبنى"],
    "additional_number": ["additional number", "الرقم الإضافي"],
    "postal_code": ["postal code", "postcode", "zip", "الرمز البريدي"],
    "short_address": ["short address", "العنوان المختصر"],
    "university": ["university", "college", "school", "institution", "الجامعة"],
    "degree": ["degree", "qualification", "education level", "المؤهل", "الدرجة العلمية", "المستوى التعليمي"],
    "major": ["major", "field of study", "specialization", "speciality", "التخصص"],
    "graduation_year": ["graduation year", "year of graduation", "graduation", "سنة التخرج", "التخرج"],
    "gpa": ["gpa", "المعدل"],
    "job_title": ["job title", "current title", "job role", "current role", "current position", "position", "المسمى الوظيفي"],
    "company": ["company", "employer", "organization", "الشركة", "جهة العمل"],
    "years_experience": ["years of experience", "experience years", "سنوات الخبرة"],
    "expected_salary": ["expected salary", "salary expectation", "desired salary", "الراتب المتوقع"],
    "notice_period": ["notice period", "فترة الإشعار"],
    "linkedin": ["linkedin", "لينكد إن"],
    "twitter": ["twitter", "x account", "x handle", "x profile", "تويتر", "حساب إكس", "حساب اكس"],
    "instagram": ["instagram", "انستغرام", "انستقرام"],
    "snapchat": ["snapchat", "snap", "سناب شات", "سناب"],
    "tiktok": ["tiktok", "تيك توك"],
    "facebook": ["facebook", "فيسبوك"],
    "youtube": ["youtube", "يوتيوب"],
    "telegram": ["telegram", "تيليجرام", "تلقرام"],
    "github": ["github"],
    "website": ["website", "portfolio", "personal site", "الموقع الشخصي"],
    "cover_letter": ["cover letter", "motivation", "خطاب التقديم", "الخطاب"],
    "cv_path": ["cv", "resume", "curriculum", "السيرة الذاتية"],
    "photo_path": ["personal photo", "profile photo", "profile picture", "photo", "picture", "الصورة الشخصية", "صورة شخصية", "صورة"],
    "id_copy_path": ["id copy", "copy of id", "national id copy", "iqama copy", "صورة الهوية", "صورة البطاقة", "نسخة الهوية"],
    "national_address_path": ["national address document", "proof of address", "وثيقة العنوان الوطني", "إثبات العنوان"],
    "certificate_path": ["certificate", "certification", "certificates", "الشهادة", "الشهادات", "شهادة"],
    "certificate_name": ["certificate name", "certification name", "اسم الشهادة"],
    "ielts_score": ["ielts score", "ielts", "آيلتس", "ايلتس"],
    "toefl_score": ["toefl score", "toefl", "توفل"],
    "step_score": ["step score", "step test score", "ستيب", "اختبار ستيب"],
    "qiyas_score": ["qiyas score", "qiyas", "قياس"],
    "ielts_date": ["ielts date", "ielts test date", "تاريخ ايلتس"],
    "toefl_date": ["toefl date", "toefl test date", "تاريخ توفل"],
    "step_date": ["step date", "step test date", "تاريخ ستيب"],
    "qiyas_date": ["qiyas date", "qiyas test date", "تاريخ قياس"],
    "ielts_path": ["ielts certificate", "ielts result", "ielts report", "نتيجة ايلتس"],
    "toefl_path": ["toefl certificate", "toefl result", "toefl report", "نتيجة توفل"],
    "step_path": ["step certificate", "step result", "step report", "نتيجة ستيب"],
    "qiyas_path": ["qiyas certificate", "qiyas result", "qiyas report", "نتيجة قياس"],
}

# Standard HTML autocomplete hints (many sloppy sites still set these)
AUTOCOMPLETE = {
    "given-name": "first_name", "additional-name": "second_name", "family-name": "last_name",
    "name": "full_name", "email": "email", "tel": "phone", "tel-national": "phone", "bday": "dob",
    "country-name": "country", "country": "country", "address-level1": "region",
    "address-level2": "city", "street-address": "street", "address-line1": "street",
    "postal-code": "postal_code", "organization": "company", "organization-title": "job_title",
    "url": "website", "sex": "gender",
}


def autocomplete_key(attr):
    for tok in reversed((attr or "").lower().split()):
        if tok in AUTOCOMPLETE:
            return AUTOCOMPLETE[tok]
    return None


FILE_KEYS = {"cv_path", "photo_path", "id_copy_path", "national_address_path", "certificate_path",
             "ielts_path", "toefl_path", "step_path", "qiyas_path"}

SKIP_TYPES = {"hidden", "submit", "button", "reset", "image", "password", "checkbox"}

DESCRIBE_JS = """
el => {
  const t = (el.type || el.tagName).toLowerCase();
  let label = '';
  if (el.id) {
    const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
    if (l) label += ' ' + l.innerText;
  }
  const pl = el.closest('label'); if (pl) label += ' ' + pl.innerText;
  const lb = el.getAttribute('aria-labelledby');
  if (lb) lb.split(' ').forEach(i => { const n = document.getElementById(i); if (n) label += ' ' + n.innerText; });
  const fs = el.closest('fieldset');
  const legend = fs && fs.querySelector('legend') ? fs.querySelector('legend').innerText : '';
  let prev = '';
  let n = el;
  for (let hop = 0; hop < 2 && !prev && n; hop++) {
    let ps = n.previousSibling;
    while (ps && ps.nodeType === 3 && !ps.textContent.trim()) ps = ps.previousSibling;
    if (ps && ps.nodeType === 3) prev = ps.textContent.trim().slice(0, 60);
    else if (ps && ps.nodeType === 1) {
      const t = (ps.innerText || '').trim();
      if (t && t.length <= 60 && !ps.querySelector('input,select,textarea')) prev = t;
    }
    n = n.parentElement;
  }
  const box = el.closest('fieldset,[role=radiogroup],.form-group,.form-field') || (el.parentElement && el.parentElement.parentElement) || el.parentElement;
  const ctx = box ? box.innerText.slice(0, 150) : '';
  return {
    type: t, tag: el.tagName.toLowerCase(), name: el.name || '', id: el.id || '',
    placeholder: el.placeholder || '', aria: el.getAttribute('aria-label') || '',
    label: label, legend: legend, ctx: ctx, value: el.value || '',
    autocomplete: el.getAttribute('autocomplete') || '', title: el.getAttribute('title') || '',
    prev: prev, rtl: getComputedStyle(el).direction === 'rtl',
    required: !!el.required || el.getAttribute('aria-required') === 'true',
    opts: el.tagName === 'SELECT' ? [...el.options].slice(0, 12).map(o => o.text.trim()) : [],
    visible: (() => {
      if (!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)) return false;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) return false;
      const r = el.getBoundingClientRect();
      if (r.right + scrollX <= 0 || r.bottom + scrollY <= 0) return false;  // pushed off the page (honeypot trick)
      return r.width >= 2 && r.height >= 2;
    })(),
    disabled: !!(el.disabled || el.readOnly)
  };
}
"""


def norm(s, split_camel=True):
    s = s or ""
    if split_camel:
        s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)  # firstName -> first Name
    s = s.lower()
    s = re.sub(r"['’`]", "", s)  # father's -> fathers
    s = re.sub(r"[\u064B-\u0652\u0640]", "", s)  # تشكيل وتطويل
    s = re.sub("[أإآ]", "ا", s).replace("ى", "ي").replace("ة", "ه")
    s = re.sub(r"[_\-\.\*:/()\[\]]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


NORM_KEYWORDS = {k: [norm(w) for w in v] for k, v in KEYWORDS.items()}


def kw_in(kw, text):
    if re.search(r"[a-z]", kw):  # كلمة انجليزية: لازم تكون كلمة كاملة
        return re.search(r"(?<![a-z])" + re.escape(kw) + r"(?![a-z])", text) is not None
    return kw in text


def match_key(text):
    """يرجع المفتاح اللي أطول كلمة له موجودة في النص."""
    # نجرب بتقسيم الحروف الكبيرة (firstName) وبدونه (GitHub, LinkedIn)
    texts = {norm(text, True), norm(text, False)}
    best_len, best_key = 0, None
    for key, kws in NORM_KEYWORDS.items():
        for kw in kws:
            if len(kw) > best_len and any(kw_in(kw, t) for t in texts):
                best_len, best_key = len(kw), key
    return best_key


# Used only when your profile has no value for the key (you can override any of them in profile.json)
DEFAULTS = {
    "phone_device_type": ["Mobile", "Mobile Phone", "Cell", "Cellular", "جوال"],
    "phone_country_code": ["Saudi Arabia (+966)", "+966", "Saudi Arabia", "السعودية"],
}


def get_value(profile, key, arabic, strict=False):
    """strict=True: the field explicitly asks for Arabic or Latin/English, so never fall back to the other one."""
    order = (["ar"] if arabic else ["en"]) if strict else (["ar", "en"] if arabic else ["en", "ar"])
    for suffix in order:
        v = profile.get(f"{key}_{suffix}")
        if v not in (None, "", []):
            return v
    v = profile.get(key)
    if v not in (None, "", []):
        return v
    return DEFAULTS.get(key)


def lang_pref(d):
    """(arabic?, strict?) from the field's own text: 'Arabic ...' / 'Latin Script' / Arabic letters / RTL."""
    t = " ".join([d["label"], d["placeholder"], d["aria"], d["title"], d["prev"]])
    ex_ar = re.search(r"\barabic\b|بالعربي|بالعربية", t, re.I)
    ex_en = re.search(r"\blatin\b|\benglish\b|بالانجليزي|بالإنجليزية", t, re.I)
    ar = bool(ex_ar) or (not ex_en and (bool(re.search(r"[\u0600-\u06FF]", t)) or
                                         (d["rtl"] and not re.search(r"[A-Za-z]", t))))
    return ar, bool(ex_ar or ex_en)


def candidates(v):
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def pick_option(options, cands):
    """options: [(value, text)] -> يرجع value الخيار المناسب."""
    for exact in (True, False):
        for c in cands:
            nc = norm(c)
            for val, text in options:
                nt = norm(text)
                if not val or not nt:
                    continue
                if (nt == nc) if exact else (nc in nt):
                    return val
    return None


def classify(d):
    """Decide which profile key a field is for. Returns (key, how, shown_name, own_text)."""
    own = " ".join([d["label"], d["name"], d["id"], d["placeholder"], d["aria"], d["title"]])
    shown = (d["label"] or d["placeholder"] or d["title"] or d["name"] or d["id"]
             or d["aria"] or d["autocomplete"] or d["prev"]).strip()[:50]
    if d["type"] == "radio":
        key = match_key(" ".join([d["name"], d["legend"], d["ctx"]]))
        return key, ("group text" if key else None), shown, own
    if own.strip():
        key = match_key(own)
        if key:
            return key, "label/name/id", shown, own
    key = autocomplete_key(d["autocomplete"])
    if key:
        return key, "autocomplete", shown, own
    if d["prev"]:
        key = match_key(d["prev"])
        if key:
            return key, "nearby text", shown, own
    if not own.strip():
        key = match_key(d["ctx"])
        if key:
            return key, "surrounding text", shown, own
    return None, None, shown, own

# ---- قوائم منسدلة مخصصة (div role=combobox) ----
COMBO_JS = """
el => {
  const clean = s => (s || '').replace(/\\s+/g, ' ').trim();
  let label = el.getAttribute('aria-label') || '';
  const lb = el.getAttribute('aria-labelledby');
  if (!label && lb) lb.split(' ').forEach(i => { const n = document.getElementById(i); if (n) label += ' ' + n.innerText; });
  const lab = (id) => { if (!id) return ''; const l = document.querySelector('label[for="' + CSS.escape(id) + '"]'); return l ? l.innerText : ''; };
  if (!label.trim()) label = lab(el.id);
  const inner = el.querySelector('input');
  if (!label.trim() && inner) label = lab(inner.id) || inner.getAttribute('aria-label') || '';
  let n = el;
  for (let hop = 0; hop < 4 && !label.trim() && n; hop++) {
    n = n.parentElement;
    if (!n) break;
    const l = [...n.querySelectorAll('label, legend')].find(x => !x.contains(el) && !el.contains(x));
    if (l) label = l.innerText;
  }
  let prev = '';
  n = el;
  for (let hop = 0; hop < 3 && !prev && n; hop++) {
    let s = n.previousElementSibling;
    while (s && !prev) { const t = clean(s.innerText); if (t && t.length <= 60) prev = t; s = s.previousElementSibling; }
    n = n.parentElement;
  }
  return {
    label: clean(label).slice(0, 80), prev: prev, text: clean(el.innerText).slice(0, 60),
    disabled: el.getAttribute('aria-disabled') === 'true' || !!el.disabled,
    visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
    hasInput: el.tagName === 'INPUT' || !!inner,
    rtl: getComputedStyle(el).direction === 'rtl'
  };
}
"""

PLACEHOLDER_TEXT = {"", "select", "choose", "please select", "select...", "choose...", "-", "--", "اختر", "اختيار"}

OPTION_JS = """
() => [...document.querySelectorAll('[role=option], [role=listbox] li, ul[role=listbox] > *')]
  .map((e, i) => ({i, t: (e.innerText || e.textContent || '').trim().slice(0, 80),
                   v: !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)}))
  .filter(o => o.v && o.t)
"""


def combo_desc(el):
    c = el.evaluate(COMBO_JS)
    d = {"label": c["label"], "name": "", "id": "", "placeholder": "", "aria": "", "title": "",
         "prev": c["prev"], "ctx": "", "rtl": c["rtl"], "autocomplete": ""}
    return c, d


def combo_key(d):
    key = match_key(d["label"]) if d["label"].strip() else None
    if not key and d["prev"]:
        key = match_key(d["prev"])
    return key


def combo_is_empty(c):
    return norm(c["text"]) in PLACEHOLDER_TEXT


def read_options(page):
    try:
        return page.evaluate(OPTION_JS)
    except Exception:
        return []


def choose_combo(page, el, c, cands):
    """يفتح القائمة، يختار الخيار المطابق. يرجع (True, None) أو (False, [نصوص الخيارات])."""
    el.scroll_into_view_if_needed(timeout=2000)
    el.click(timeout=3000)
    page.wait_for_timeout(400)
    opts = read_options(page)
    if not opts and c["hasInput"]:  # قوائم بحث: نكتب أول كلمة ونستنى النتائج
        el.evaluate("e => { const i = e.matches('input') ? e : e.querySelector('input'); if (i) i.focus(); }")
        page.keyboard.type(cands[0][:40], delay=40)
        page.wait_for_timeout(900)
        opts = read_options(page)
    pairs = [(str(o["i"]), o["t"]) for o in opts]
    val = pick_option(pairs, cands)
    if val is not None:
        page.evaluate("""i => { const all = [...document.querySelectorAll('[role=option], [role=listbox] li, ul[role=listbox] > *')];
                              all[i].scrollIntoView({block:'nearest'}); all[i].click(); }""", int(val))
        page.wait_for_timeout(250)
        return True, None
    page.keyboard.press("Escape")
    return False, [t for _v, t in pairs]


def frame_ok(frame):
    """Fill only the main page and frames a person can actually see (not 1px or hidden ad/tracker frames)."""
    try:
        if frame.parent_frame is None:
            return True
        bb = frame.frame_element().bounding_box()
        return bool(bb) and bb["width"] >= 100 and bb["height"] >= 40
    except Exception:
        return False


def fill_page(page, profile, overwrite=False, dry_run=False):
    filled, missed = [], []
    for frame in page.frames:
        if not frame_ok(frame):
            continue
        try:
            elements = frame.query_selector_all("input, textarea, select")
        except Exception:
            continue
        for el in elements:
            try:
                d = el.evaluate(DESCRIBE_JS)
                if d["type"] in SKIP_TYPES or (not d["visible"] and d["type"] != "file") or d["disabled"]:
                    continue
                is_radio = d["type"] == "radio"
                key, _how, shown, own = classify(d)
                if not key:
                    missed.append(shown or f"(unnamed {d['type']} field, no label found)")
                    continue
                is_file = d["type"] == "file"
                if is_file and key not in FILE_KEYS:
                    alt = key.rsplit("_", 1)[0] + "_path"
                    key = alt if alt in FILE_KEYS else key
                if is_file != (key in FILE_KEYS):
                    missed.append(f"{shown}  [file/text mismatch: {key}]")
                    continue
                arabic, strict = lang_pref(d)
                value = get_value(profile, key, arabic, strict)
                if value is None:
                    need = f"{key}_{'ar' if arabic else 'en'}" if strict else key
                    missed.append(f"{shown}  [missing in your profile: {need}]")
                    continue
                cands = candidates(value)

                if d["type"] == "file":
                    path = (DATA_DIR / cands[0]).expanduser().resolve()
                    if FILES.resolve() not in path.parents:
                        missed.append(f"{shown}  [file must be inside the my_files folder]")
                        continue
                    if not path.exists():
                        missed.append(f"{shown}  [file not found: {path}]")
                        continue
                    if not dry_run:
                        el.set_input_files(str(path))
                elif d["tag"] == "select":
                    if d["value"] and not overwrite:
                        continue
                    opts = el.evaluate("e => [...e.options].map(o => [o.value, o.text])")
                    val = pick_option(opts, cands)
                    if val is None:
                        names = ", ".join(t.strip() for _v, t in opts if t.strip())[:90]
                        missed.append(f"{shown}  [no option matches your data. Options: {names}]")
                        continue
                    if not dry_run:
                        el.select_option(value=val)
                elif is_radio:
                    own_label = norm(d["label"] or "")
                    if not any(norm(c) and (norm(c) == own_label or norm(c) in own_label) for c in cands):
                        continue  # هذا مو الخيار المطلوب في المجموعة
                    if not dry_run:
                        el.check()
                else:
                    if d["value"] and not overwrite:
                        continue
                    if not dry_run:
                        el.fill(cands[0])

                if not dry_run:
                    el.evaluate("e => e.style.outline = '2px solid #2ecc71'")
                filled.append(f"{shown or key}  <-  {key}")
            except Exception as e:  # حقل واحد يفشل ما يوقف الباقي
                missed.append(f"(error on a field: {str(e)[:60]})")
        try:
            combos = frame.query_selector_all("[role=combobox]:not(input):not(select)")
        except Exception:
            combos = []
        for el in combos:
            try:
                c, d = combo_desc(el)
                if not c["visible"] or c["disabled"]:
                    continue
                key = combo_key(d)
                shown = (c["label"] or c["prev"] or "(unlabeled dropdown)")[:50]
                if not key:
                    missed.append(f"{shown}  [dropdown, not recognised]")
                    continue
                if not combo_is_empty(c) and not overwrite:
                    continue
                arabic, strict = lang_pref(d)
                value = get_value(profile, key, arabic, strict)
                if value is None:
                    need = f"{key}_{'ar' if arabic else 'en'}" if strict else key
                    missed.append(f"{shown}  [missing in your profile: {need}]")
                    continue
                if key in FILE_KEYS:
                    continue
                if dry_run:
                    filled.append(f"{shown}  <-  {key}  (dropdown)")
                    continue
                ok, names = choose_combo(page, el, c, candidates(value))
                if ok:
                    filled.append(f"{shown}  <-  {key}  (dropdown)")
                else:
                    shown_opts = ", ".join(names)[:90] if names else "list did not open"
                    missed.append(f"{shown}  [no option matches your data. Options: {shown_opts}]")
            except Exception as e:
                missed.append(f"(error on a dropdown: {str(e)[:60]})")
    return filled, missed


CUSTOM_JS = """
() => [...document.querySelectorAll('[role=listbox],[role=textbox],[contenteditable=true],[role=radiogroup],[role=checkbox]')]
  .filter(e => !e.matches('input,select,textarea') && (e.offsetWidth || e.offsetHeight))
  .slice(0, 40).map(e => ({role: e.getAttribute('role') || 'contenteditable',
     text: (e.getAttribute('aria-label') || e.innerText || '').trim().slice(0, 50)}))
"""


def scan_page(page, profile):
    """Read-only report of every field on the page. Never writes values, never prints your data."""
    rows, custom = [], []
    for frame in page.frames:
        if not frame_ok(frame):
            continue
        try:
            custom += frame.evaluate(CUSTOM_JS)
            elements = frame.query_selector_all("input, textarea, select")
        except Exception:
            continue
        for el in elements:
            try:
                d = el.evaluate(DESCRIBE_JS)
                if d["type"] in ("hidden", "submit", "button", "reset", "image") or (not d["visible"] and d["type"] != "file"):
                    continue
                key, how, shown, _own = classify(d)
                is_file = d["type"] == "file"
                if d["type"] in ("checkbox", "password"):
                    status = f"MANUAL ({d['type']})"
                elif d["disabled"]:
                    status = "DISABLED"
                elif not key:
                    status = "UNMATCHED"
                else:
                    if is_file and key not in FILE_KEYS:
                        alt = key.rsplit("_", 1)[0] + "_path"
                        key = alt if alt in FILE_KEYS else key
                    if is_file != (key in FILE_KEYS):
                        status = f"MISMATCH ({key})"
                    elif get_value(profile, key, *lang_pref(d)) is None:
                        status = f"NO DATA ({key})"
                    else:
                        status = f"OK ({key}, via {how})"
                rows.append({"status": status, "type": d["type"], "name_shown": shown,
                             "label": d["label"].strip()[:60], "placeholder": d["placeholder"][:40],
                             "html_name": d["name"], "html_id": d["id"], "autocomplete": d["autocomplete"],
                             "nearby_text": d["prev"][:40], "required": d["required"],
                             "options": d["opts"][:8]})
            except Exception as e:
                rows.append({"status": "ERROR", "name_shown": str(e)[:60]})
        try:
            for el in frame.query_selector_all("[role=combobox]:not(input):not(select)"):
                c, d = combo_desc(el)
                if not c["visible"]:
                    continue
                key = combo_key(d)
                shown = (c["label"] or c["prev"] or "(unlabeled dropdown)")[:50]
                if c["disabled"]:
                    status = "DISABLED"
                elif not key:
                    status = "UNMATCHED"
                elif get_value(profile, key, *lang_pref(d)) is None:
                    status = f"NO DATA ({key})"
                elif not combo_is_empty(c):
                    status = f"ALREADY SET ({key})"
                else:
                    status = f"OK ({key}, dropdown)"
                rows.append({"status": status, "type": "dropdown", "name_shown": shown,
                             "label": c["label"][:60], "placeholder": "", "html_name": "", "html_id": "",
                             "autocomplete": "", "nearby_text": c["prev"][:40], "required": False, "options": []})
        except Exception:
            pass
    url = page.url
    report = {"site": urlparse(url).netloc or url[:60], "title": page_title(page)[:80],
              "time": time.strftime("%Y-%m-%d %H:%M"), "fields": rows, "custom_widgets": custom}
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    host = re.sub(r"[^\w.-]", "_", report["site"])[:40] or "page"
    path = SCAN_DIR / f"{host}_{stamp}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report, path


def print_scan(report, path):
    f = report["fields"]
    count = lambda pre: sum(1 for r in f if r["status"].startswith(pre))
    print(f"\n[SCAN] {report['site']} | {report['title']}")
    print(f"[SCAN] fields: {len(f)} | OK {count('OK')} | NO DATA {count('NO DATA')} | "
          f"UNMATCHED {count('UNMATCHED')} | MISMATCH {count('MISMATCH')} | manual {count('MANUAL')} | "
          f"custom widgets: {len(report['custom_widgets'])}")
    for r in f:
        tag = r["status"]
        if tag.startswith("OK"):
            print(f"   {tag:34} {r['name_shown']}")
        else:
            extra = []
            if r.get("html_name"): extra.append(f"name={r['html_name']}")
            if r.get("html_id"): extra.append(f"id={r['html_id']}")
            if r.get("nearby_text"): extra.append(f"near='{r['nearby_text']}'")
            if r.get("options"): extra.append("options=" + "/".join(r["options"][:5]))
            print(f"   {tag:34} [{r.get('type','')}] {r.get('name_shown','')}  " + " ".join(extra))
    for c in report["custom_widgets"][:15]:
        print(f"   CUSTOM WIDGET (not supported)      role={c['role']} '{c['text']}'")
    print(f"[SCAN] saved: {path}  (contains field names only, none of your data)")


def page_title(pg):
    try:
        return pg.title()
    except Exception:
        return ""


def browser_alive(ctx):
    """False once the user has closed the browser window."""
    try:
        pages = [pg for pg in ctx.pages if not pg.is_closed()]
        if not pages:
            return False
        pages[0].evaluate("1")
        return True
    except Exception:
        return False


def load_profile(pf):
    profile = json.loads(Path(pf).read_text(encoding="utf-8"))
    certs = [c for c in profile.get("certificates", []) if isinstance(c, dict) and c.get("path")]
    if certs:
        if not profile.get("certificate_path"):
            profile["certificate_path"] = certs[0]["path"]
        if not profile.get("certificate_name") and certs[0].get("name"):
            profile["certificate_name"] = certs[0]["name"]
    return profile


def worker_main(argv=None):
    ap = argparse.ArgumentParser(description="Auto-fill job application forms")
    ap.add_argument("--profile", default=str(PROFILE), help="path to your profile JSON file")
    ap.add_argument("--overwrite", action="store_true", help="overwrite fields that already have a value")
    ap.add_argument("--dry-run", action="store_true", help="show what would be filled, without filling")
    ap.add_argument("--chrome", action="store_true",
                    help="use your installed Google Chrome instead of the bundled Chromium")
    ap.add_argument("--url", default="", help="open this application page when the browser starts")
    args = ap.parse_args(argv)

    pf = Path(args.profile)
    if not pf.exists():
        sys.exit("profile.json not found. Copy profile.example.json to profile.json and fill in your data.")
    profile = load_profile(pf)
    if not sys.stdout.isatty():  # when launched from the UI, keep Arabic output safe
        for st in (sys.stdout, sys.stderr):
            try:
                st.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            except Exception:
                pass

    from playwright.sync_api import sync_playwright
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    headless = os.environ.get("AUTOFILL_HEADLESS") == "1"  # used for automated tests only
    with sync_playwright() as p:
        if args.chrome:
            ctx = p.chromium.launch_persistent_context(
                str(CHROME_SESSION_DIR), channel="chrome", headless=headless, no_viewport=True,
                chromium_sandbox=SANDBOX)
        else:
            ctx = p.chromium.launch_persistent_context(
                str(SESSION_DIR), headless=headless, no_viewport=True, chromium_sandbox=SANDBOX)
        if not ctx.pages:
            ctx.new_page()
        if args.url:
            try:
                ctx.pages[0].goto(args.url, wait_until="domcontentloaded", timeout=60000)
            except Exception as e:
                print(f"[!] Could not open the URL: {str(e)[:120]}")
        print("job-autofill by Reyof (@4lavc)")
        print("[READY] Browser is open. Open the application page, then choose it and fill.")
        print("The tool never submits the application. Review and submit it yourself.")
        while True:
            print("\n[Enter] fill the newest page  |  list  |  fill N  |  scan N  |  q = quit:", flush=True)
            try:
                raw = input()
            except EOFError:
                break
            cmd = raw.strip().lower()
            if cmd in ("q", "quit"):
                break
            if not browser_alive(ctx):
                print("[CLOSED] The browser window was closed. Click 'Open browser' again.", flush=True)
                break
            if cmd == "ping":
                print("[OPENED] browser already open", flush=True)
                continue
            mo = re.fullmatch(r"open\s+(\S+)", raw.strip(), re.I)
            if mo:
                url = mo.group(1)
                if not re.match(r"^https?://", url, re.I):
                    print("[!] The link must start with http:// or https://", flush=True)
                    continue
                try:
                    pg = ctx.new_page()
                    print(f"[OPENED] new tab: {urlparse(url).netloc}", flush=True)
                    pg.goto(url, wait_until="domcontentloaded", timeout=60000)
                    pg.bring_to_front()
                except Exception as e:
                    print(f"[!] Could not open the link: {str(e)[:100]}", flush=True)
                continue
            pages = [pg for pg in ctx.pages if not pg.is_closed()]
            if cmd == "list":
                print("[PAGES] " + json.dumps(
                    [{"i": i, "title": page_title(pg), "url": pg.url} for i, pg in enumerate(pages)],
                    ensure_ascii=False), flush=True)
                continue
            if cmd == "" or cmd.startswith(("fill", "scan")):
                try:  # pick up changes saved in the UI since the browser was opened
                    profile = load_profile(pf)
                except Exception as e:
                    print(f"[!] Could not re-read profile.json ({str(e)[:80]}). Using the previous data.")
            ms = re.fullmatch(r"scan(?:\s+(\d+))?", cmd)
            if ms:
                i = int(ms.group(1)) if ms.group(1) else len(pages) - 1
                if not pages or i >= len(pages):
                    print("[!] That page is not open anymore. Refresh the page list.")
                    continue
                print_scan(*scan_page(pages[i], profile))
                continue
            m = re.fullmatch(r"fill\s+(\d+)", cmd)
            if m:
                idx = int(m.group(1))
            elif cmd in ("", "fill"):
                idx = len(pages) - 1
            else:
                print("[!] Unknown command. Use: list, fill N, q")
                continue
            if not pages or idx >= len(pages):
                print("[!] That page is not open anymore. Refresh the page list.")
                continue
            page = pages[idx]
            filled, missed = fill_page(page, profile, args.overwrite, args.dry_run)
            print(f"\n[OK] {'Would fill' if args.dry_run else 'Filled'}: {len(filled)}  "
                  f"(page {idx + 1}: {page_title(page)[:50] or page.url[:50]})")
            for f in filled:
                print("   -", f)
            if missed:
                print(f"\n[!] Fill these yourself ({len(missed)}):")
                for m2 in missed:
                    print("   -", m2)
        try:
            ctx.close()
        except Exception:
            pass


# ======================================================================
#  Part 2: the local web server (the UI talks to this)
# ======================================================================
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024


@app.before_request
def guard():
    # Only this computer, and only our own page, may talk to the server.
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and origin not in ORIGINS:
            abort(403)


def err(msg, code=400):
    return jsonify(error=msg), code


@app.get("/")
def index():
    return UI_HTML, 200, {"Content-Type": "text/html; charset=utf-8", "X-Content-Type-Options": "nosniff",
                          "Content-Security-Policy": "frame-ancestors 'none'"}


@app.get("/files/<path:name>")
def files(name):
    return send_from_directory(FILES, name)


@app.get("/api/profile")
def get_profile():
    src = PROFILE if PROFILE.exists() else EXAMPLE
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except Exception as e:
        return err(f"ملف البيانات فيه خطأ: {e}")
    data.setdefault("certificates", [])
    return jsonify(data)


@app.post("/api/profile")
def save_profile():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return err("بيانات غير صالحة")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return jsonify(ok=True)


def slug(text):
    s = re.sub(r"[^\w\-]+", "_", text.strip(), flags=re.UNICODE).strip("_")[:50]
    return s or "file"


@app.post("/api/upload")
def upload():
    kind = request.form.get("kind", "")
    f = request.files.get("file")
    if not f or not f.filename:
        return err("ما وصل ملف")
    ext = Path(f.filename).suffix.lower()
    allowed = EXTS | ({".docx"} if kind == "cv" else set())
    if ext not in allowed:
        return err("نوع الملف غير مدعوم. المسموح: " + " ".join(sorted(allowed)))
    FILES.mkdir(parents=True, exist_ok=True)
    if kind == "certificate":
        d = FILES / "certificates"
        d.mkdir(parents=True, exist_ok=True)
        stem = slug(request.form.get("name") or Path(f.filename).stem)
        target, n = d / f"{stem}{ext}", 2
        while target.exists():
            target, n = d / f"{stem}_{n}{ext}", n + 1
    elif kind in KINDS:
        for old in FILES.glob(KINDS[kind] + ".*"):
            old.unlink()
        target = FILES / (KINDS[kind] + ext)
    else:
        return err("نوع غير معروف")
    f.save(target)
    return jsonify(path=target.relative_to(DATA_DIR).as_posix())


@app.post("/api/delete")
def delete_file():
    rel = (request.get_json(silent=True) or {}).get("path", "")
    p = (DATA_DIR / rel).resolve()
    if FILES.resolve() in p.parents and p.is_file():
        p.unlink()
    return jsonify(ok=True)


# ---------- privacy: your data stays with your computer ----------
def _machine_id():
    try:
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0])
        if sys.platform == "darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True,
                                 text=True, timeout=5).stdout
            m = re.search(r'"IOPlatformUUID" = "([^"]+)"', out)
            if m:
                return m.group(1)
        for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if Path(f).exists():
                return Path(f).read_text().strip()
    except Exception:
        pass
    return "fallback-" + socket.gethostname()


def device_fingerprint():
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    return hashlib.sha256(f"{_machine_id()}|{user}".encode()).hexdigest()


def wipe_personal(extra=()):
    """Delete everything personal: profile, uploaded files, saved browser sessions, scan reports."""
    p = RUN.get("proc")
    if p is not None and p.poll() is None:  # close the browser first (Windows locks its files)
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            pass
    return _remove(list(PERSONAL) + list(extra))


def _remove(items):
    n = 0
    for item in items:
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                n += 1
            elif item.exists():
                item.unlink()
                n += 1
        except Exception:
            pass
    return n


def check_device():
    """If this data folder came from another computer/user, delete it. True if something was wiped."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except Exception:
        pass
    fp = device_fingerprint()
    wiped = False
    if DEVICE_MARK.exists():
        try:
            same = DEVICE_MARK.read_text().strip() == fp
        except Exception:
            same = False
        if not same:
            wiped = wipe_personal() > 0
    DEVICE_MARK.write_text(fp)
    return wiped


# ---------- log privacy: nothing personal leaves this file in the log ----------
# Values from these keys are not personal (they are shown as-is so problems stay debuggable).
SAFE_KEYS = {"gender", "nationality", "country", "degree", "major", "notice_period", "years_experience",
             "gpa", "phone_device_type", "phone_country_code", "graduation_year"}
NAME_KEYS = ("first_name", "second_name", "third_name", "last_name", "full_name")
_RED = {"mtime": object(), "pat": None}
_URL_Q = re.compile(r"(https?://[^\s?#]+)[?#]\S*", re.I)
_EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_USERPATH = re.compile(r"((?:users|home)[\\/])[^\\/\s]+", re.I)
_LONGNUM = re.compile(r"\d{9,}")


def _flatten(v, key=""):
    if isinstance(v, dict):
        for k, x in v.items():
            yield from _flatten(x, str(k))
    elif isinstance(v, list):
        for x in v:
            yield from _flatten(x, key)
    elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
        yield key, str(v)


def _refresh_redactor():
    try:
        mt = PROFILE.stat().st_mtime
    except OSError:
        mt = None
    if _RED["mtime"] == mt:
        return
    pats = set()
    if mt is not None:
        try:
            data = json.loads(PROFILE.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        for key, val in _flatten(data):
            base = re.sub(r"_(ar|en)$", "", key)
            val = val.strip()
            if base in SAFE_KEYS or key.endswith("_path") or key == "path" or not val or len(val) > 200:
                continue
            if len(val) >= 3 and not (val.isdigit() and len(val) < 5):
                pats.add(re.escape(val))
            if base in NAME_KEYS:
                pats.update(re.escape(w) for w in re.split(r"\s+", val) if len(w) >= 3)
            digits = re.sub(r"\D", "", val)
            if base.startswith(("phone", "national_id", "iqama", "id")) and len(digits) >= 7:
                core = digits[-9:] if len(digits) > 9 else digits
                pats.add(r"[\s\-().]*".join(core))
    _RED["pat"] = re.compile("|".join(sorted(pats, key=len, reverse=True)), re.I) if pats else None
    _RED["mtime"] = mt


def redact(line):
    if line.startswith("job-autofill by Reyof (@4lavc)"):
        return line
    _refresh_redactor()
    line = _URL_Q.sub(lambda m: m.group(1) + "?[hidden]", line)
    if _RED["pat"]:
        line = _RED["pat"].sub("[hidden]", line)
    line = _EMAIL.sub("[email]", line)
    line = _USERPATH.sub(r"\1[user]", line)
    return _LONGNUM.sub("[number]", line)


# ---------- running the filler (autofill.py as a child process) ----------
LOCK = threading.Lock()
RUN = {"proc": None, "log": []}
STATE = {"wiped": False}


def _reader(proc):
    for line in proc.stdout:
        line = line.rstrip("\n")
        if not line.startswith("[PAGES] "):  # the page list is used by the UI only, never shown in the log
            try:
                line = redact(line)
            except Exception:
                line = "[line hidden: could not be checked for personal data]"
        with LOCK:
            if len(RUN["log"]) < 3000 or line.startswith("[PAGES] "):
                RUN["log"].append(line)


def _alive():
    p = RUN["proc"]
    return p is not None and p.poll() is None


@app.post("/api/autofill/start")
def af_start():
    opts = request.get_json(silent=True) or {}
    url = str(opts.get("url") or "").strip()
    if url and (not re.match(r"^https?://", url, re.I) or re.search(r"[\s\x00-\x1f\x7f]", url)):
        return err("رابط الصفحة لازم يبدأ بـ http:// أو https:// وبدون مسافات")
    if _alive():
        # Browser process is running: open the link in a new tab (or detect that the window was closed).
        with LOCK:
            start = len(RUN["log"])
        try:
            RUN["proc"].stdin.write((f"open {url}\n") if url else "ping\n")
            RUN["proc"].stdin.flush()
        except Exception:
            pass
        deadline = time.time() + 25
        while time.time() < deadline:
            with LOCK:
                new_lines = RUN["log"][start:]
            if any(ln.startswith("[OPENED]") for ln in new_lines):
                return jsonify(ok=True, new_process=False)
            if any(ln.startswith("[CLOSED]") for ln in new_lines) or not _alive():
                break
            time.sleep(0.2)
        else:
            return jsonify(ok=True, new_process=False)
        try:  # the browser was closed: clean up the old process and start a fresh one below
            RUN["proc"].wait(timeout=5)
        except Exception:
            try:
                RUN["proc"].terminate()
            except Exception:
                pass
    if not PROFILE.exists():
        return err("احفظ بياناتك أول، بعدين شغّل التعبئة")
    if importlib.util.find_spec("playwright") is None:
        return err("مكتبة playwright غير مثبتة. شغّل start.bat (أو start.sh) بدل التشغيل المباشر")
    cmd = [sys.executable, "-u", str(Path(__file__).resolve()), "--worker", "--profile", str(PROFILE)]
    if opts.get("chrome"):
        cmd.append("--chrome")
    if opts.get("dry"):
        cmd.append("--dry-run")
    if url:
        cmd += ["--url", url]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(cmd, cwd=BASE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    with LOCK:
        RUN["proc"], RUN["log"] = proc, []
    threading.Thread(target=_reader, args=(proc,), daemon=True).start()
    return jsonify(ok=True, new_process=True)


@app.get("/api/info")
def info():
    return jsonify(data_dir=str(DATA_DIR), wiped=STATE["wiped"], legacy=any(x.exists() for x in LEGACY))


@app.post("/api/legacy")
def legacy():
    action = (request.get_json(silent=True) or {}).get("action")
    if action == "delete":
        _remove(LEGACY)
        return jsonify(ok=True)
    if action != "migrate":
        return err("إجراء غير معروف")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for old, new in zip(LEGACY, PERSONAL):
        if old.exists() and not new.exists():
            shutil.move(str(old), str(new))
    for old in LEGACY:  # anything left (the new location already had it): remove the copy inside the tool folder
        if old.is_dir():
            shutil.rmtree(old, ignore_errors=True)
        elif old.exists():
            old.unlink()
    return jsonify(ok=True)


@app.post("/api/wipe")
def wipe_all():
    wipe_personal(extra=LEGACY)
    return jsonify(ok=True)


@app.post("/api/autofill/fill")
def af_fill():
    if not _alive():
        return err("افتح المتصفح أول (زر ١)")
    idx = (request.get_json(silent=True) or {}).get("index")
    cmd = f"fill {int(idx)}\n" if isinstance(idx, int) else "\n"
    try:
        RUN["proc"].stdin.write(cmd)
        RUN["proc"].stdin.flush()
    except Exception:
        return err("المتصفح انسكر. افتحه من جديد")
    return jsonify(ok=True)


@app.post("/api/autofill/scan")
def af_scan():
    if not _alive():
        return err("افتح المتصفح أول (زر ١)")
    idx = (request.get_json(silent=True) or {}).get("index")
    cmd = f"scan {int(idx)}\n" if isinstance(idx, int) else "scan\n"
    try:
        RUN["proc"].stdin.write(cmd)
        RUN["proc"].stdin.flush()
    except Exception:
        return err("المتصفح انسكر. افتحه من جديد")
    return jsonify(ok=True)


@app.get("/api/autofill/pages")
def af_pages():
    if not _alive():
        return jsonify(pages=[], running=False)
    with LOCK:
        start = len(RUN["log"])
    try:
        RUN["proc"].stdin.write("list\n")
        RUN["proc"].stdin.flush()
    except Exception:
        return jsonify(pages=[], running=False)
    deadline = time.time() + 6
    while time.time() < deadline:
        with LOCK:
            new = RUN["log"][start:]
        for ln in new:
            if ln.startswith("[PAGES] "):
                try:
                    return jsonify(pages=json.loads(ln[8:]), running=True)
                except ValueError:
                    pass
        time.sleep(0.15)
    return jsonify(pages=[], running=True)


@app.post("/api/autofill/stop")
def af_stop():
    p = RUN["proc"]
    if p is not None and p.poll() is None:
        try:
            p.stdin.write("q\n")
            p.stdin.flush()
            p.wait(timeout=5)
        except Exception:
            p.terminate()
    return jsonify(ok=True)


@app.get("/api/autofill/status")
def af_status():
    since = request.args.get("since", 0, type=int)
    with LOCK:
        if since > len(RUN["log"]):  # a new browser process started: send its log from the beginning
            since = 0
        lines = RUN["log"][since:]
        nxt = len(RUN["log"])
    return jsonify(running=_alive(), lines=lines, next=nxt)


@atexit.register
def _cleanup():
    p = RUN["proc"]
    if p is not None and p.poll() is None:
        p.terminate()


# ======================================================================
#  Entry point
# ======================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker_main(sys.argv[2:])
    else:
        STATE["wiped"] = check_device()
        url = f"http://127.0.0.1:{PORT}"
        print(f"\njob-autofill by Reyof (@4lavc)\nافتح المتصفح على: {url}\nللإيقاف: اضغط Ctrl+C في هذه النافذة\n")
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
