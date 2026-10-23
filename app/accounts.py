"""Local owner account, scrypt passwords and RFC 6238 TOTP. No external service."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from urllib.parse import quote
from hub import write_private


def password_hash(password, salt=None):
    salt=salt or secrets.token_hex(16)
    value=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex()
    return {'salt':salt,'hash':value}


def password_matches(password, record):
    if not isinstance(password,str) or len(password)>1024:return False
    return hmac.compare_digest(password_hash(password,record['salt'])['hash'],record['hash'])


def totp(secret, step, digits=6):
    key=base64.b32decode(secret+'='*((-len(secret))%8))
    value=hmac.new(key,struct.pack('!Q',step),hashlib.sha1).digest();offset=value[-1]&15
    return str((struct.unpack('!I',value[offset:offset+4])[0]&0x7fffffff)%(10**digits)).zfill(digits)


def code_step(secret,code,now=None):
    code=str(code).strip()
    if not re.fullmatch(r'[0-9]{6}',code):return None
    current=int((time.time() if now is None else now)//30)
    for step in (current,current-1,current+1):
        if hmac.compare_digest(totp(secret,step),code):return step
    return None


def recovery_hash(code):return hashlib.sha256(str(code).strip().replace('-','').lower().encode()).hexdigest()

class AccountMixin:
    def init_accounts(self):
        path=self.dir/'account.json'
        self.account=json.loads(path.read_text()) if path.exists() else None
        self.pending_totp={}
    def account_public(self):
        a=self.account or {}
        return {'configured':bool(a),'username':a.get('username',''),'two_factor':bool(a.get('totp_secret')),'recovery_remaining':len(a.get('recovery',[]))}
    def save_account(self):write_private(self.dir/'account.json',self.account)
    def second_factor(self,code):
        a=self.account
        if not a.get('totp_secret'):return True
        step=code_step(a['totp_secret'],code)
        if step is not None and step>a.get('last_step',-1):
            a['last_step']=step;self.save_account();return True
        hashed=recovery_hash(code)
        for old in a.get('recovery',[]):
            if hmac.compare_digest(old,hashed):
                a['recovery'].remove(old);self.save_account();return True
        return False
    def verify_owner(self,password,code=''):
        if self.account:return password_matches(password,self.account['password']) and self.second_factor(code)
        return isinstance(password,str) and hmac.compare_digest(password.encode(),self.password.encode())
    def login_owner(self,data):
        if self.account and not hmac.compare_digest(str(data.get('username','')).encode(),self.account['username'].encode()):return False
        return self.verify_owner(data.get('password',''),data.get('code',''))
    def account_action(self,data,session):
        with self.lock:
            # Sensitive actions have their own limit, in addition to login throttling.
            now=time.time();key='account:'+session
            history=[t for t in self.attempts.get(key,[]) if now-t<300]
            if len(history)>=10:raise ValueError('Te veel accountpogingen; wacht vijf minuten.')
            self.attempts[key]=history+[now]
            action=data.get('action','save')
            if action=='confirm':
                pending=self.pending_totp.get(session)
                if not pending or pending['expires']<now:raise ValueError('2FA-aanvraag verlopen; begin opnieuw.')
                step=code_step(pending['secret'],data.get('code',''))
                if step is None:raise ValueError('Ongeldige 2FA-code; controleer ook de tijd op je NUC en telefoon.')
                codes=[secrets.token_hex(8) for _ in range(10)]
                self.account.update(totp_secret=pending['secret'],last_step=step,recovery=[recovery_hash(c) for c in codes])
                self.save_account();self.pending_totp.clear();self.sessions.clear()
                self.attempts.pop(key,None)
                return {'ok':True,'recovery_codes':codes,'login_again':True}
            if not self.verify_owner(data.get('current_password',''),data.get('code','')):raise ValueError('Controleer je huidige wachtwoord en eventuele 2FA- of herstelcode.')
            if action=='save':
                name=str(data.get('username','')).strip()
                if not re.fullmatch(r'[\w.@-]{1,80}',name):raise ValueError('Gebruik 1–80 letters, cijfers, punten, @, - of _ voor je gebruikersnaam.')
                password=data.get('password','')
                if not isinstance(password,str) or not 12<=len(password)<=1024:raise ValueError('Kies een nieuw wachtwoord van minimaal 12 en maximaal 1024 tekens.')
                self.account={**(self.account or {}),'username':name,'password':password_hash(password)}
                self.save_account();self.sessions.clear();self.pending_totp.clear()
                result={'ok':True,'login_again':True}
            elif action=='setup':
                if not self.account:raise ValueError('Maak eerst je eigen account aan.')
                if self.account.get('totp_secret'):raise ValueError('2FA is al ingeschakeld.')
                secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
                self.pending_totp={session:{'secret':secret,'expires':now+600}}
                result={'secret':secret,'uri':'otpauth://totp/'+quote('VenGuard:'+self.account['username'],safe='')+'?secret='+secret+'&issuer=VenGuard&algorithm=SHA1&digits=6&period=30'}
            elif action=='disable':
                if not self.account:raise ValueError('Maak eerst je eigen account aan.')
                for k in ('totp_secret','last_step','recovery'):self.account.pop(k,None)
                self.save_account();self.sessions.clear();self.pending_totp.clear();result={'ok':True,'login_again':True}
            else:raise ValueError('Ongeldige accountactie.')
            self.attempts.pop(key,None);return result
