(function(){
  const sendOtp=document.getElementById('sendOtp');
  if(sendOtp){
    sendOtp.addEventListener('click', async function(){
      const email=(document.getElementById('signupEmail')||{}).value?.trim().toLowerCase();
      const msg=document.getElementById('otpMessage');
      if(!email){msg.textContent='Enter your email first.';return;}
      sendOtp.disabled=true;msg.textContent='Sending verification code…';
      try{
        const csrf=document.querySelector('meta[name=csrf-token]')?.content || ''; const r=await fetch('/api/auth/send-otp',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({target:email})});
        const data=await r.json();msg.textContent=data.message||'Done.';
        if(!r.ok) throw new Error(data.message||'Unable to send OTP');
        let left=60;const original='Send OTP';const timer=setInterval(()=>{left--;sendOtp.textContent=left?`Resend in ${left}s`:original;if(!left){clearInterval(timer);sendOtp.disabled=false;}},1000);
      }catch(e){sendOtp.disabled=false;}
    });
  }
  const files=document.getElementById('mediaFiles');
  const summary=document.getElementById('fileSummary');
  if(files){files.addEventListener('change',()=>{const n=files.files.length;let bytes=[...files.files].reduce((a,f)=>a+f.size,0);summary.textContent=n?`${n} file${n>1?'s':''} selected · ${(bytes/1024/1024).toFixed(1)} MB total`:'';});}
  const form=document.getElementById('eventForm');
  if(form){form.addEventListener('submit',async(e)=>{e.preventDefault();const btn=form.querySelector('button[type=submit]'),out=document.getElementById('uploadMessage');btn.disabled=true;out.textContent='Creating event and uploading media…';try{const csrf=document.querySelector('meta[name=csrf-token]')?.content || '';const r=await fetch('/api/events/create',{method:'POST',headers:{'X-CSRF-Token':csrf},body:new FormData(form)});const type=r.headers.get('content-type')||'';const data=type.includes('application/json')?await r.json():{message:'Server returned an unexpected response.'};if(!r.ok)throw new Error(data.message||'Upload failed');out.textContent=data.message||'Upload complete.';setTimeout(()=>location.reload(),700);}catch(err){out.textContent=err.message||'Upload failed.';btn.disabled=false;}});}
})();
