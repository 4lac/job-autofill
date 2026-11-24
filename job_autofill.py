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
import io
import json
import mimetypes
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

from flask import Flask, abort, jsonify, request, send_file

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
PROFILE = DATA_DIR / "profile.enc"          # encrypted
PLAIN_PROFILE = DATA_DIR / "profile.json"  # only exists before the first encryption
EXAMPLE = BASE / "profile.example.json"
DEVICE_MARK = DATA_DIR / ".device"
KEY_FILE = DATA_DIR / ".key"  # only used when the system key store is not available
ENC = ".enc"
KEY_SERVICE = "job-autofill"
PERSONAL = [PROFILE, PLAIN_PROFILE, KEY_FILE, FILES, SESSION_DIR, CHROME_SESSION_DIR, SCAN_DIR]
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
#  Encryption: your profile and uploaded files are stored encrypted
# ======================================================================
class KeyLost(Exception):
    """Encrypted data exists but its key is gone (e.g. Windows reinstalled)."""


_KEY = {"v": None, "mode": None}


def _keyring():
    try:
        import keyring
        kr = keyring.get_keyring()
        if getattr(kr, "priority", 1) <= 0:  # the "fail" backend: no real key store on this system
            return None
        return keyring
    except Exception:
        return None


def _has_encrypted():
    return PROFILE.exists() or (FILES.exists() and any(FILES.rglob("*" + ENC)))


def get_key():
    if _KEY["v"]:
        return _KEY["v"]
    kr = _keyring()
    key = None
    if kr:
        try:
            key = kr.get_password(KEY_SERVICE, "data-key")
        except Exception:
            kr, key = None, None
        if key:
            _KEY.update(v=key.encode(), mode="keyring")
            return _KEY["v"]
    if KEY_FILE.exists():
        _KEY.update(v=KEY_FILE.read_text().strip().encode(), mode="file")
        return _KEY["v"]
    if _has_encrypted():
        raise KeyLost()
    from cryptography.fernet import Fernet
    new = Fernet.generate_key()
    if kr:
        try:
            kr.set_password(KEY_SERVICE, "data-key", new.decode())
            _KEY.update(v=new, mode="keyring")
            return new
        except Exception:
            pass
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_text(new.decode())
    try:
        os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    _KEY.update(v=new, mode="file")
    return new


def enc_bytes(b):
    from cryptography.fernet import Fernet
    return Fernet(get_key()).encrypt(b)


def dec_bytes(b):
    from cryptography.fernet import Fernet
    return Fernet(get_key()).decrypt(b)


def read_profile_file(path):
    """Reads a profile: encrypted (profile.enc) or a plain .json (for people who bring their own file)."""
    raw = Path(path).read_bytes()
    if raw[:6] == b"gAAAAA":  # every encrypted token starts like this
        raw = dec_bytes(raw)
    return json.loads(raw.decode("utf-8"))


def write_profile(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE.write_bytes(enc_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")))


def phys(path):
    """Uploaded files are stored as <name>.enc; this is that location for a logical path."""
    return Path(str(path) + ENC)


def read_stored_file(path):
    p = phys(path)
    if p.is_file():
        return dec_bytes(p.read_bytes())
    if Path(path).is_file():  # an old unencrypted file, until the next start migrates it
        return Path(path).read_bytes()
    return None


def encrypt_plaintext():
    """Encrypt anything stored in the clear by an older version. Returns how many items changed."""
    n = 0
    if PLAIN_PROFILE.exists():
        try:
            data = json.loads(PLAIN_PROFILE.read_text(encoding="utf-8"))
        except Exception:
            data = None
        if data is not None and (not PROFILE.exists() or PLAIN_PROFILE.stat().st_mtime > PROFILE.stat().st_mtime):
            write_profile(data)
        if PROFILE.exists():
            PLAIN_PROFILE.unlink()
            n += 1
    if FILES.exists():
        for f in list(FILES.rglob("*")):
            if f.is_file() and f.suffix != ENC:
                phys(f).write_bytes(enc_bytes(f.read_bytes()))
                f.unlink()
                n += 1
    return n


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
<link rel="icon" type="image/png" href="data:image/png;base64,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">
<link rel="apple-touch-icon" href="data:image/png;base64,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">
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
  if(i.key_lost)h+='<div class="note">⚠️ بياناتك مشفّرة لكن مفتاحها ضاع (غالباً بعد إعادة تثبيت النظام)، فما أقدر أفتحها. اضغط «حذف كل بياناتي» أسفل الصفحة وابدأ من جديد.</div>';
  else if(i.key_mode==="file")h+='<div class="note">🔑 نظامك ما فيه خزنة مفاتيح، فمفتاح التشفير محفوظ في ملف جنب بياناتك (حماية أضعف). الأفضل تفعّل خزنة النظام (مثل GNOME Keyring) وتعيد التشغيل.</div>';
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
                    try:
                        blob = read_stored_file(path)
                    except Exception:
                        missed.append(f"{shown}  [could not decrypt the file]")
                        continue
                    if blob is None:
                        missed.append(f"{shown}  [file not found: {path.name}]")
                        continue
                    if not dry_run:  # sent straight from memory: a readable copy is never written to disk
                        el.set_input_files({"name": path.name, "buffer": blob,
                                            "mimeType": mimetypes.guess_type(path.name)[0] or "application/octet-stream"})
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
    profile = read_profile_file(pf)
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
    p = (FILES / name).resolve()
    if FILES.resolve() not in p.parents:
        abort(404)
    try:
        blob = read_stored_file(p)
    except Exception:
        abort(404)
    if blob is None:
        abort(404)
    return send_file(io.BytesIO(blob), mimetype=mimetypes.guess_type(p.name)[0] or "application/octet-stream",
                     max_age=0)


@app.get("/api/profile")
def get_profile():
    src = PROFILE if PROFILE.exists() else (PLAIN_PROFILE if PLAIN_PROFILE.exists() else EXAMPLE)
    try:
        data = read_profile_file(src)
    except KeyLost:
        return err("ما أقدر أفتح بياناتك المشفّرة لأن مفتاحها ضاع (مثلاً بعد إعادة تثبيت ويندوز). اضغط «حذف كل بياناتي» وابدأ من جديد.")
    except Exception as e:
        return err(f"ملف البيانات فيه خطأ: {e}")
    data.setdefault("certificates", [])
    return jsonify(data)


@app.post("/api/profile")
def save_profile():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return err("بيانات غير صالحة")
    try:
        write_profile(data)
    except KeyLost:
        return err("مفتاح التشفير ضاع. اضغط «حذف كل بياناتي» وابدأ من جديد.")
    except Exception as e:
        return err(f"ما قدرت أحفظ: {e}")
    if PLAIN_PROFILE.exists():
        PLAIN_PROFILE.unlink()
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
        while phys(target).exists():
            target, n = d / f"{stem}_{n}{ext}", n + 1
    elif kind in KINDS:
        for old in FILES.glob(KINDS[kind] + ".*"):
            old.unlink()
        target = FILES / (KINDS[kind] + ext)
    else:
        return err("نوع غير معروف")
    try:
        phys(target).write_bytes(enc_bytes(f.read()))
    except KeyLost:
        return err("مفتاح التشفير ضاع. اضغط «حذف كل بياناتي» وابدأ من جديد.")
    except Exception as e:
        return err(f"ما قدرت أحفظ الملف: {e}")
    return jsonify(path=target.relative_to(DATA_DIR).as_posix())


@app.post("/api/delete")
def delete_file():
    rel = (request.get_json(silent=True) or {}).get("path", "")
    p = (DATA_DIR / rel).resolve()
    if FILES.resolve() in p.parents:
        for q in (p, phys(p)):
            if q.is_file():
                q.unlink()
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
            data = read_profile_file(PROFILE)
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
    if not (PROFILE.exists() or PLAIN_PROFILE.exists()):
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
    key_lost = False
    try:
        get_key()
    except KeyLost:
        key_lost = True
    except Exception:
        pass
    return jsonify(data_dir=str(DATA_DIR), wiped=STATE["wiped"], legacy=any(x.exists() for x in LEGACY),
                   key_mode=_KEY["mode"], key_lost=key_lost)


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
    try:
        encrypt_plaintext()
    except Exception:
        pass
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
        try:
            encrypt_plaintext()
        except Exception:
            pass
        url = f"http://127.0.0.1:{PORT}"
        print(f"\njob-autofill by Reyof (@4lavc)\nافتح المتصفح على: {url}\nللإيقاف: اضغط Ctrl+C في هذه النافذة\n")
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
