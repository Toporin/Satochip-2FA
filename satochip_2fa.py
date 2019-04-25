#!/usr/bin/env python
#

import time
from xmlrpc.client import ServerProxy

#kivy
from kivy.app import App
from kivy.uix.widget import Widget
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.properties import ListProperty
from kivy.clock import Clock
from kivy.properties import NumericProperty, StringProperty, BooleanProperty, ObjectProperty
from kivy.uix.gridlayout import GridLayout
from kivy.uix.tabbedpanel import TabbedPanel

import sys
import traceback
from hashlib import sha1, sha256
import hmac

import cryptos
from cryptos.coins import Bitcoin

server = ServerProxy('https://cosigner.electrum.org/', allow_none=True)
secret_2FA=b'\0'*20 

IS_TESTNET= True
APPROVE_TX="Approve tx!"
REJECT_TX="Reject tx!"


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

class OkButton(Button):
    btn_approve_tx= StringProperty(APPROVE_TX)

class CancelButton(Button):
    btn_reject_tx= StringProperty(REJECT_TX)        

# class Container(GridLayout):

    # display = ObjectProperty()
    # btn_disabled= BooleanProperty(False)
    
    # def __init__(self, **kwargs):
        # super(Container, self).__init__(**kwargs)
        # self.listener = Listener(self)
        # mac = hmac.new(secret_2FA, "id_2FA".encode('utf-8'), sha256)
        # id_2FA= mac.hexdigest()
        # mac = hmac.new(secret_2FA, "key_2FA".encode('utf-8'), sha256)
        # key_2FA= mac.hexdigest()
        # self.listener.set_keyhashes([id_2FA])     
        # self.btc= Bitcoin(IS_TESTNET)
        
    # def approve_tx(self, btn):        
        # letter= self.listener.postbox.pop()
        # keyhash= letter[0]
        # pre_tx_hex=letter[1]
        # pre_tx= bytes.fromhex(pre_tx_hex)
        # pre_tx_dic= cryptos.deserialize(pre_tx_hex)
        # print("pre_tx_dic: ", pre_tx_dic)
        # self.display.text = str(pre_tx_dic)
        # # compute tx_hash
        # pre_hash= sha256(pre_tx).digest()
        # pre_hash= sha256(pre_hash).digest()
        # pre_hash= pre_hash+ (b'\0'*32) # 32bytes zero-padding
        # pre_hash_hex= pre_hash.hex()
        # print("tx_hash: ", pre_hash_hex)
        # #compute  response to challenge and send back...
        # if (btn.text == APPROVE_TX):
            # mac = hmac.new(secret_2FA, pre_hash, sha1)
            # reply= mac.hexdigest()
            # self.display.text = "Tx approved!"
        # else: 
            # reply= "00"*20
            # self.display.text = "Tx rejected!"
        # print("response sent: ", reply)
        # replyhash= sha256(keyhash.encode('utf-8')).hexdigest()
        # #todo: encrypt reply
        # print("Sent response to: ", replyhash)
        # server.put(replyhash, reply)
        # self.listener.clear(keyhash)
        # self.btn_disabled= False

    # def update(self, dt):
    # #def update(self):
        # print("Update...")
        # for keyhash in self.listener.keyhashes:
            # if keyhash in self.listener.received:
                # continue
            # try:
                # message = server.get(keyhash)
                # message="0200000001cc81d38a9e782801bcba30ab5a26d92a8ec1018eeea144fbc09c694e53794de6010000001976a9143f3c6ae42382a8a8e5c9766f8384db5049792b8b88acfdffffff02a0860100000000001976a914752c77c03a0f86057458e978494ea2a0245cfb3788ac073a4900000000001976a914e105877f9e0a3acecf842c9cf905a09eef26a76588ac55bb160001000000" #debug
                # self.listener.postbox.append([keyhash,message])
                # self.listener.received.add(keyhash)
            # except Exception as e:
                # print("cannot contact server")
                # break
            # if message:
                # print("received challenge for ", keyhash)
                # print("challenge received: ", message)
                # #todo: decrypt message
                # #parse tx
                # pre_tx_hex=message
                # pre_tx= bytes.fromhex(pre_tx_hex)
                # pre_tx_dic= cryptos.deserialize(pre_tx_hex)
                # print("pre_tx_dic: ", pre_tx_dic)
                # # too: show clear message for approval
                # amount_in=0
                # txt=""
                # ins= pre_tx_dic['ins']
                # nb_ins= len(ins)
                # txt+="nb_inputs: "+str(nb_ins) + "\n"
                # txt+="inputs:\n"
                # for i in ins:
                    # script= i['script']
                    # #txt+="    "+"script: "+script+"\n"
                    # #scripts= cryptos.deserialize_script(script)
                    # addr= self.btc.scripttoaddr(script)
                    # unspent=  self.btc.unspent(addr)
                    # val= 0
                    # for d in unspent:
                        # val+=d['value']
                    # txt+="    "+"address: "+addr+" unspent: "+str(val)+"\n"
                    # amount_in+=val
                # txt+="    "+"total: "+str(amount_in)+"\n"
                    
                # fee=0
                # amount_out=0
                # outs= pre_tx_dic['outs']
                # nb_outs= len(outs)
                # txt+="nb_outputs: "+str(nb_outs) + "\n"
                # txt+="outputs:\n"
                # for o in outs:
                    # script= o['script']
                    # val= o['value']
                    # addr= self.btc.scripttoaddr(script)
                    # txt+="    "+"address: "+addr+" spent: "+str(val)+"\n"
                    # #txt+="    "+"script: "+script+"\n"
                    # #txt+="    "+"value: "+str(val)+"\n"
                    # amount_out+=val
                # txt+="    "+"total: "+str(amount_out)+"\n"
                # fee= amount_in-amount_out
                # txt+="    "+"fees:  "+str(fee)+"\n"
                
                # print(txt)
                # self.display.text = txt
                # self.btn_disabled= False
                # break

class Tabs(TabbedPanel):
    #display = ObjectProperty()
    display = StringProperty('Waiting tx...')
    btn_disabled= BooleanProperty(True)
    
    def __init__(self, **kwargs):
        super(Tabs, self).__init__(**kwargs)
        self.listener = Listener(self)
        mac = hmac.new(secret_2FA, "id_2FA".encode('utf-8'), sha256)
        id_2FA= mac.hexdigest()
        mac = hmac.new(secret_2FA, "key_2FA".encode('utf-8'), sha256)
        key_2FA= mac.hexdigest()
        self.listener.set_keyhashes([id_2FA])     
        self.btc= Bitcoin(IS_TESTNET)
        
    def approve_tx(self, btn):        
        letter= self.listener.postbox.pop()
        keyhash= letter[0]
        pre_tx_hex=letter[1]
        pre_tx= bytes.fromhex(pre_tx_hex)
        pre_tx_dic= cryptos.deserialize(pre_tx_hex)
        print("pre_tx_dic: ", pre_tx_dic)
        self.display = str(pre_tx_dic)
        # compute tx_hash
        pre_hash= sha256(pre_tx).digest()
        pre_hash= sha256(pre_hash).digest()
        pre_hash= pre_hash+ (b'\0'*32) # 32bytes zero-padding
        pre_hash_hex= pre_hash.hex()
        print("tx_hash: ", pre_hash_hex)
        #compute  response to challenge and send back...
        if (btn.text == APPROVE_TX):
            mac = hmac.new(secret_2FA, pre_hash, sha1)
            reply= mac.hexdigest()
            self.display = "Tx approved!"
        else: 
            reply= "00"*20
            self.display = "Tx rejected!"
        print("response sent: ", reply)
        replyhash= sha256(keyhash.encode('utf-8')).hexdigest()
        #todo: encrypt reply
        print("Sent response to: ", replyhash)
        server.put(replyhash, reply)
        self.listener.clear(keyhash)
        self.btn_disabled= False

    def update(self, dt):
    #def update(self):
        print("Update...")
        for keyhash in self.listener.keyhashes:
            if keyhash in self.listener.received:
                continue
            try:
                message = server.get(keyhash)
                message="0200000001cc81d38a9e782801bcba30ab5a26d92a8ec1018eeea144fbc09c694e53794de6010000001976a9143f3c6ae42382a8a8e5c9766f8384db5049792b8b88acfdffffff02a0860100000000001976a914752c77c03a0f86057458e978494ea2a0245cfb3788ac073a4900000000001976a914e105877f9e0a3acecf842c9cf905a09eef26a76588ac55bb160001000000" #debug
                self.listener.postbox.append([keyhash,message])
                self.listener.received.add(keyhash)
            except Exception as e:
                print("cannot contact server")
                break
            if message:
                print("received challenge for ", keyhash)
                print("challenge received: ", message)
                #todo: decrypt message
                #parse tx
                pre_tx_hex=message
                pre_tx= bytes.fromhex(pre_tx_hex)
                pre_tx_dic= cryptos.deserialize(pre_tx_hex)
                print("pre_tx_dic: ", pre_tx_dic)
                # too: show clear message for approval
                amount_in=0
                txt=""
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
                
                print(txt)
                self.display = txt
                self.btn_disabled= False
                break
                
class SatochipSecondFactorApp(App):
    
    
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

    
    def build(self):
        self.title = 'Satochip 2-Factor Authentication App'
        root = Tabs()
        Clock.schedule_interval(root.update, 3.0)
        #root2 = Container()
        #Clock.schedule_interval(root2.update, 3.0)
        return root #RootWidget()
        
    

if __name__ == '__main__':
    SatochipSecondFactorApp().run()

        