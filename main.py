from kivy.app import App
from kivy.uix.widget import Widget
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.properties import StringProperty, BooleanProperty, ObjectProperty
from kivy.clock import Clock
from kivy.utils import platform

from hashlib import sha1, sha256
import hmac
import urllib3
import requests
from cryptos import deserialize
from cryptos.coins import Bitcoin
from xmlrpc.client import ServerProxy

server = ServerProxy('https://cosigner.electrum.org/', allow_none=True)
DEBUG=True
DEBUG_SECRET_2FA=b'\0'*20 

IS_TESTNET=True
APPROVE_TX="Approve tx!"
REJECT_TX="Reject tx!"
LOG_SEP="-"*60 + "\n"

class Listener():
    def __init__(self, parent):
        self.parent = parent
        self.received = set()
        self.keyhashes = []
        self.postbox = []

    def set_keyhashes(self, keyhashes):
        self.keyhashes = keyhashes

    def clear(self, keyhash):
        server.delete(keyhash)
        self.received.remove(keyhash)

class Factors():
    def __init__(self):
        self.factors={}
        
    def save_to_mem(self):
        pass
        
    def load_from_mem(self):
        pass
        
    def add_new_factor(self,secret_2FA, label):
        d={}
        d['label_2FA']=label
        d['secret_2FA']= secret_2FA #bytearray
        mac = hmac.new(secret_2FA, "id_2FA".encode('utf-8'), sha256)
        d['id_2FA']=id_2FA= mac.hexdigest()
        mac = hmac.new(secret_2FA, "cryptkey_2FA".encode('utf-8'), sha256)
        d['cryptkey_2FA']= mac.hexdigest()
        d['idreply_2FA']=sha256(id_2FA.encode('utf-8')).hexdigest()
        self.factors['id_2FA']=d
        self.save_to_mem()
        
    def remove_factor(self, id):
        self.factors.pop(id)
        self.save_to_mem()

class OkButton(Button):
    btn_approve_tx= StringProperty(APPROVE_TX) 
    
class CancelButton(Button):
    btn_reject_tx= StringProperty(REJECT_TX)             

#class Satochip(GridLayout):
class Satochip(TabbedPanel):
    btn_disabled= BooleanProperty(True)
    btn_approve_qr_disabled= BooleanProperty(True)
    
    display = StringProperty('Waiting tx...')
    label_qr_data= StringProperty("Click on 'scan' button to scan a new QR code...")
    label_logs= StringProperty('Contains the tx history...\n'+LOG_SEP)
    label_2FA_label= StringProperty('Enter 2FA description here')
    
    def __init__(self, **kwargs):
        super(Satochip, self).__init__(**kwargs)
        self.myfactors= Factors()
        self.myfactors.load_from_mem()
        if DEBUG:
            self.myfactors.add_new_factor(DEBUG_SECRET_2FA, "Debug-2FA")
            
        self.listener = Listener(self)
        self.btc= Bitcoin(IS_TESTNET)
        
        
    def approve_tx(self, btn): 
        letter= self.listener.postbox.pop()
        keyhash= letter[0]
        pre_tx_hex=letter[1]
        pre_tx= bytes.fromhex(pre_tx_hex)
               
        # compute tx_hash
        pre_hash= sha256(pre_tx).digest()
        pre_hash= sha256(pre_hash).digest()
        pre_hash= pre_hash+ (b'\0'*32) # 32bytes zero-padding
        pre_hash_hex= pre_hash.hex()
        print("SatochipDebug:"+"tx_hash: ", pre_hash_hex)
        
        #compute  response to challenge and send back...
        if (btn.text == APPROVE_TX):
            secret_2FA=self.myfactors.factors[keyhash]['secret_2FA']
            mac = hmac.new(secret_2FA, pre_hash, sha1)
            reply= mac.hexdigest()
            self.display = "Tx approved!"
        else: 
            reply= "00"*20
            self.display = "Tx rejected!"
        print("SatochipDebug:"+"response sent: ", reply)
        replyhash2= sha256(keyhash.encode('utf-8')).hexdigest()
        replyhash= self.myfactors.factors[keyhash]['idreply_2FA']
        if (replyhash!=replyhash2):
            print("Error! replyhash incorrect!")
            
        #todo: encrypt reply
        print("SatochipDebug:"+"Sent response to: ", replyhash)
        server.put(replyhash, reply)
        self.listener.clear(keyhash)
        self.btn_disabled= True
        self.label_logs+= "Tx approved" +"\n"+LOG_SEP
    
    def update(self, dt):
        print("SatochipDebug:"+"Update...")
        for keyhash, dic in self.myfactors.factors.items():
            if keyhash in self.listener.received:
                continue
            try:
                message = server.get(keyhash)
                #message="0200000001cc81d38a9e782801bcba30ab5a26d92a8ec1018eeea144fbc09c694e53794de6010000001976a9143f3c6ae42382a8a8e5c9766f8384db5049792b8b88acfdffffff02a0860100000000001976a914752c77c03a0f86057458e978494ea2a0245cfb3788ac073a4900000000001976a914e105877f9e0a3acecf842c9cf905a09eef26a76588ac55bb160001000000" #debug
                self.listener.postbox.append([keyhash,message])
                self.listener.received.add(keyhash)
            except Exception as e:
                print("SatochipDebug:"+"cannot contact server")
                break
            if message:
                label= self.myfactors.factors[keyhash]['label_2FA']
                if DEBUG:
                    print("Satochip: received challenge for ", keyhash)
                    print("Satochip: corresponding label", label)
                    print("Satochip: challenge received: ", message)
                #todo: decrypt message
                
                # parse tx into a clear message for approval
                pre_tx_hex=message
                pre_tx= bytes.fromhex(pre_tx_hex)
                pre_tx_dic= deserialize(pre_tx_hex)
                if DEBUG: 
                    print("Satochip pre_tx_dic: ", str(pre_tx_dic))
                
                # show 
                txt="2FA: "+label+"\n" 
                amount_in=0
                ins= pre_tx_dic['ins']
                nb_ins= len(ins)
                txt+="nb_inputs: "+str(nb_ins) + "\n"
                txt+="inputs:\n"
                for i in ins:
                    script= i['script']
                    #txt+="    "+"script: "+script+"\n"
                    #scripts= cryptos.deserialize_script(script)
                    addr= self.btc.scripttoaddr(script)
                    unspent=  self.btc.unspent(addr)
                    val= 0
                    for d in unspent:
                        val+=d['value']
                    txt+="    "+"address: "+addr+" unspent: "+str(val)+"\n"
                    amount_in+=val
                txt+="    "+"total: "+str(amount_in)+"\n"
                    
                fee=0
                amount_out=0
                outs= pre_tx_dic['outs']
                nb_outs= len(outs)
                txt+="nb_outputs: "+str(nb_outs) + "\n"
                txt+="outputs:\n"
                for o in outs:
                    script= o['script']
                    val= o['value']
                    addr= self.btc.scripttoaddr(script)
                    txt+="    "+"address: "+addr+" spent: "+str(val)+"\n"
                    #txt+="    "+"script: "+script+"\n"
                    #txt+="    "+"value: "+str(val)+"\n"
                    amount_out+=val
                txt+="    "+"total: "+str(amount_out)+"\n"
                fee= amount_in-amount_out
                txt+="    "+"fees:  "+str(fee)+"\n"
                
                if DEBUG: 
                    print("Satochip tx:"+txt)
                self.display = txt
                self.btn_disabled= False
                self.label_logs+= txt +"\n"
                break
    
    def scan_qr(self, on_complete):
        if platform != 'android':
            return
        from jnius import autoclass, cast
        from android import activity
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        SimpleScannerActivity = autoclass("org.electrum.qr.SimpleScannerActivity")
        Intent = autoclass('android.content.Intent')
        intent = Intent(PythonActivity.mActivity, SimpleScannerActivity)

        def on_qr_result(requestCode, resultCode, intent):
            try:
                if resultCode == -1:  # RESULT_OK:
                    #  this doesn't work due to some bug in jnius:
                    # contents = intent.getStringExtra("text")
                    String = autoclass("java.lang.String")
                    contents = intent.getStringExtra(String("text"))
                    on_complete(contents)
            finally:
                activity.unbind(on_activity_result=on_qr_result)
        activity.bind(on_activity_result=on_qr_result)
        PythonActivity.mActivity.startActivityForResult(intent, 0)
    
    def on_qr(self, data):
        self.label_qr_data= data.strip()
        self.btn_approve_qr_disabled=False
        
    def on_approve_qr(self):
        if DEBUG:
            print("secret:"+self.label_qr_data+" label:"+ self.label_2FA_label) 
        
        try: 
            secret_2FA= bytearray.fromhex(self.label_qr_data)
            self.myfactors.add_new_factor(secret_2FA, self.label_2FA_label)
            self.label_qr_data= "QR code added!"
            self.label_logs+= "Second factor added with label:" +"\n"+self.label_2FA_label+"\n"+LOG_SEP
        except ValueError:
            print("Error: the qr code should provide a hexadecimal value")
            self.label_logs+= "Error: the qr code should provide a hexadecimal value"+"\n"+LOG_SEP
        self.btn_approve_qr_disabled=True
        
        
       
class TestApp(App):
    def build(self):
        self.title = 'Satochip 2-Factor Authentication App'
        root= Satochip()
        Clock.schedule_interval(root.update, 3.0)
        return root

if __name__ == '__main__':
    TestApp().run()