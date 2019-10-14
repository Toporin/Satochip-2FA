#
# Satochip 2-Factor-Authentication app for the Satochip Bitcoin Hardware Wallet
# (c) 2019 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
# Sources available on https://github.com/Toporin	
# 				 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from kivy.app import App
from kivy.uix.widget import Widget
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.properties import StringProperty, BooleanProperty, ObjectProperty
from kivy.clock import Clock
from kivy.utils import platform
from kivy.storage.jsonstore import JsonStore
from kivy.logger import Logger
from kivy.logger import LoggerHistory

from datetime import datetime
import logging
from os import urandom
from hashlib import sha1, sha256
import pyaes
import hmac
import certifi
import urllib3
import requests
import ssl
import json
import base64
from cryptos import transaction, main #deserialize
from cryptos.coins import Bitcoin, BitcoinCash, Litecoin
from cryptos.main import num_to_var_int
from cashaddress import convert # cashAddr conversion for bcash
from xmlrpc.client import ServerProxy

from TxParser import TxParser
#import segwit_addr

ca_path = certifi.where()
#print("CA Path: "+ca_path)
context = ssl.SSLContext()
context.verify_mode =  ssl.CERT_REQUIRED
context.check_hostname = True
context.load_verify_locations(ca_path)
server = ServerProxy('https://cosigner.electrum.org/', allow_none=True, context=context)

# # xmlrpc server for bcash
# from xmlrpc.client import ServerProxy, Transport
# import http.client 
# # Workarounds to the fact that xmlrpc.client doesn't take a timeout= arg.
# class TimeoutTransport(Transport):
    # def __init__(self, timeout=2.0, *l, **kw):
        # super().__init__(*l, **kw)
        # self.timeout = timeout
    # def make_connection(self, host):
        # return http.client.HTTPConnection(host, timeout=self.timeout)
# class TimeoutServerProxy(ServerProxy):
    # def __init__(self, uri, timeout=2.0, *l, **kw):
        # kw['transport'] = TimeoutTransport(timeout=timeout, use_datetime=kw.get('use_datetime', False))
        # super().__init__(uri, *l, **kw)
# # /end timeout= Workarounds
# server = TimeoutServerProxy('http://sync.imaginary.cash:8081', allow_none=True,  timeout = 2.0)

DEBUG=True
DEBUG_SECRET_2FA= "00"*20  #b'\0'*20
APPROVE_TX="Approve tx!"
REJECT_TX="Reject tx!"
LOG_SEP="-"*60 + "\n"
BLOCKSIZE= 16

if DEBUG: 
    Logger.setLevel(logging.DEBUG)
else: 
    Logger.setLevel(logging.INFO)

class Listener():
    def __init__(self, parent):
        self.parent = parent
        self.received = set()
        self.postbox = []

    def clear(self, keyhash):
        server.delete(keyhash)
        self.received.remove(keyhash)

class Factors():
    def __init__(self):
        self.datastore = JsonStore('data.json')
        
    def add_new_factor(self,secret_2FA, label_2FA):
        mac = hmac.new(bytes.fromhex(secret_2FA), "id_2FA".encode('utf-8'), sha1)
        id_2FA_20b= mac.hexdigest()
        id_2FA= sha256(mac.digest()).hexdigest()
        mac = hmac.new(bytes.fromhex(secret_2FA), "key_2FA".encode('utf-8'), sha1)
        key_2FA= mac.hexdigest()[0:32] # keep first 16 bytes out of 20
        idreply_2FA=sha256(id_2FA.encode('utf-8')).hexdigest()
        self.datastore.put(id_2FA, secret_2FA=secret_2FA, key_2FA= key_2FA, label_2FA=label_2FA, idreply_2FA=idreply_2FA, id_2FA_20b=id_2FA_20b)
        Logger.info("Satochip: \nAdded new factor on "+ str(datetime.now())+"\n"
                            +"label: "+ label_2FA+"\n"
                            +"id_2FA: "+ id_2FA+"\n"
                            +"idreply_2FA: "+ idreply_2FA)
        #Logger.debug("Satochip: secret_2FA"+ secret_2FA)
        #Logger.debug("Satochip: key_2FA: "+ key_2FA)
        
    def remove_factor(self, id):
        if self.datastore.exists(id):
            self.datastore.delete(id)
    
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
    label_2FA_stored= StringProperty('')
    
    def __init__(self, **kwargs):
        super(Satochip, self).__init__(**kwargs)
        self.listener = Listener(self)
        self.myfactors= Factors()
        if DEBUG:
            self.myfactors.add_new_factor(DEBUG_SECRET_2FA, "Debug-2FA")
        self.load_list_2FA()
        
        #load log history
        for record in  reversed(LoggerHistory.history):
            print(str(record))
            if record.levelno>=20: #INFO
                msg= record.getMessage()
                if msg.startswith("[Satochip"):
                    self.label_logs+=msg.replace("[Satochip    ] ","",1) +"\n"+LOG_SEP                     
        
    def load_list_2FA(self):
        self.label_2FA_stored="List of stored 2FA:\n\n"
        for keyhash in self.myfactors.datastore.keys():
            self.label_2FA_stored+="label: "+self.myfactors.datastore.get(keyhash)['label_2FA']+"\n"+"id: "+keyhash[0:32]+"...\n"+LOG_SEP
        
    def approve_tx(self, btn): 
        letter= self.listener.postbox.pop()
        keyhash= letter[0]
        challenge= letter[1]
        
        #compute  response to challenge and send back...
        reply= challenge+":"
        if (btn.text == APPROVE_TX):
            secret_2FA=bytes.fromhex(self.myfactors.datastore.get(keyhash)['secret_2FA'])
            mac = hmac.new(secret_2FA, bytes.fromhex(challenge), sha1)
            reply+= mac.hexdigest()
            self.display = "Action approved!"
            self.label_logs+= "Action approved" +"\n"+LOG_SEP
            Logger.info("Satochip: APPROVED action with hash: "+challenge+" on "+str(datetime.now()))
        else: 
            reply+= "00"*20
            self.display = "Tx rejected!"
            self.label_logs+= "Tx rejected" +"\n"+LOG_SEP
            Logger.info("Satochip: REJECTED tx with hash: "+challenge+" on "+str(datetime.now()))
        Logger.debug("Satochip: Challenge-response: "+ reply)
        replyhash= self.myfactors.datastore.get(keyhash)['idreply_2FA']
          
        # pad & encrypt reply
        key_2FA= bytes.fromhex(self.myfactors.datastore.get(keyhash)['key_2FA'])
        iv= urandom(16)
        Logger.debug("Satochip: IV hex: "+ iv.hex())
        plaintext= reply.encode("utf-8")
        encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key_2FA, iv))
        ciphertext = encrypter.feed(plaintext)
        ciphertext += encrypter.feed()
        ciphertext = iv+ciphertext
        reply_encrypt= base64.b64encode(ciphertext).decode('ascii')
        Logger.debug("Satochip: Reply_encrypt: "+reply_encrypt)
        
        # send reply to server
        Logger.debug("Satochip: Sent response to: "+replyhash)
        server.put(replyhash, reply_encrypt)
        self.listener.clear(keyhash)
        self.btn_disabled= True
        
    
    def update(self, dt):
        # only one factor at a time
        if len(self.listener.received)!=0:
            return
         
        # poll server for each id_2FA
        print("Satochip update...")
        for keyhash in self.myfactors.datastore.keys():
            # if keyhash in self.listener.received:
                # continue
            try:
                message = server.get(keyhash)
            except Exception as e:
                self.display = "Error: cannot contact server:"+str(e)
                Logger.warning("Satochip: cannot contact server: "+str(e))
                break
            if message:
                self.listener.received.add(keyhash)
                label= self.myfactors.datastore.get(keyhash)['label_2FA']
                Logger.debug("Satochip: Received challenge for: "+ keyhash)
                Logger.debug("Satochip: Corresponding label: "+ label)
                Logger.debug("Satochip: Challenge received: "+ message)
                
                # decrypt message & remove padding
                key_2FA= bytes.fromhex(self.myfactors.datastore.get(keyhash)['key_2FA'])
                message= base64.b64decode(message)
                iv= message[0:16]
                ciphertext= message[16:]
                
                decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key_2FA, iv))
                decrypted = decrypter.feed(ciphertext)
                decrypted += decrypter.feed()
                Logger.debug("Satochip: Challenge decrypted: "+decrypted.decode('ascii'))
                message= json.loads(decrypted) 
                if 'action' in message:
                    action= message['action']
                else:
                    action= "sign_tx"
                
                if action=="reset_seed":
                    authentikeyx= message['authentikeyx']
                    txt= "Request to reset the seed!\nAuthentikey:"+authentikeyx
                    challenge= authentikeyx + 32*'FF'
                elif action == "reset_2FA":
                    txt= "Request to reset 2FA!\nID_2FA:"+keyhash
                    try:
                        id_2FA_20b= self.myfactors.datastore.get(keyhash)['id_2FA_20b']
                    except Exception as ex: # not supported for 2FA created in app version <=0.8/0.9
                        id_2FA_20b= keyhash 
                    challenge= id_2FA_20b + 44*'AA'
                elif action == "sign_msg":
                    msg= message['msg']
                    if 'alt' in message:
                        altcoin= message['alt']
                        headersize= bytes([ len(altcoin)+17 ])
                        paddedmsgbytes = headersize + altcoin.encode('utf8') + b" Signed Message:\n" + num_to_var_int(len(msg)) + bytes(msg, 'utf-8')
                    else:
                        altcoin= "Bitcoin"
                        paddedmsgbytes = b"\x18Bitcoin Signed Message:\n" + num_to_var_int(len(msg)) + bytes(msg, 'utf-8')
          
                    txt= "Request to sign "+ altcoin +" message:\n"+msg+"\n"
                    paddedmsghash= sha256(paddedmsgbytes).hexdigest()
                    challenge= paddedmsghash + 32*"BB"
                elif action== "sign_tx":
                    is_segwit= message['sw']
                    txt="2FA: "+label+"\n" 
                        
                    # coin type: 
                    coin_type= message['ct']
                    if coin_type==0:
                        coin= Bitcoin(False)
                    elif coin_type==1: #btc testnet
                        coin= Bitcoin(True)
                    elif coin_type==2: #litecoin
                        istest= message['tn']
                        coin= Litecoin(testnet=istest)
                    elif coin_type==145: #bcash
                        istest= message['tn']
                        coin= BitcoinCash(testnet=istest)
                        is_segwit= True # bcash uses BIP143 for signature hash creation
                    else:
                        Logger.warning("Satochip: Coin not (yet) supported: "+str(coin_type))
                        coin=BaseCoin()
                    txt+="Coin: "+coin.display_name+"\n" 
                    
                    # parse tx into a clear message for approval
                    pre_tx_hex=message['tx']
                    pre_tx= bytes.fromhex(pre_tx_hex)
                    pre_hash_hex=  sha256(sha256(pre_tx).digest()).hexdigest()
                    challenge= pre_hash_hex+ 32*'00'
                    if is_segwit:
                        
                        #parse segwit tx
                        txin_type=message['ty']
                        txparser= TxParser(pre_tx)
                        while not txparser.is_parsed():
                            chunk= txparser.parse_segwit_transaction()
                            
                        Logger.debug("Satochip: hashPrevouts: "+txparser.hashPrevouts.hex())
                        Logger.debug("Satochip: hashSequence: "+txparser.hashSequence.hex())
                        Logger.debug("Satochip: txOutHash: "+txparser.txOutHash[::-1].hex())
                        Logger.debug("Satochip: txOutIndex: "+str(txparser.txOutIndexLong))
                        Logger.debug("Satochip: inputScript: "+txparser.inputScript.hex())
                        Logger.debug("Satochip: inputAmount: "+str(txparser.inputAmountLong))
                        Logger.debug("Satochip: nSequence: "+txparser.nSequence.hex())
                        Logger.debug("Satochip: hashOutputs: "+txparser.hashOutputs.hex())
                        Logger.debug("Satochip: nLocktime: "+txparser.nLocktime.hex())
                        Logger.debug("Satochip: nHashType: "+txparser.nHashType.hex())
                        
                        script= txparser.inputScript.hex()
                        if txin_type== 'p2wpkh':
                            hash= transaction.output_script_to_h160(script)
                            hash= bytes.fromhex(hash)
                            addr= coin.hash_to_segwit_addr(hash)
                            Logger.debug("Satochip: p2wpkh address: "+addr)
                        elif txin_type== 'p2wsh': #multisig-segwit
                            addr= coin.script_to_p2wsh(script)
                            Logger.debug("Satochip: p2wsh address: "+addr)
                        elif txin_type== 'p2wsh-p2sh':
                            h= transaction.output_script_to_h160(script)
                            addr= coin.p2sh_scriptaddr("0020"+h)
                            Logger.debug("Satochip: p2wsh-p2sh address: "+addr)
                        elif txin_type== 'p2wpkh-p2sh':
                            # for p2wpkh-p2sh addres is derived from script hash, see https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH_nested_in_BIP16_P2SH
                            h= transaction.output_script_to_h160(script)
                            addr= coin.p2sh_scriptaddr("0014"+h)
                            Logger.debug("Satochip: p2wpkh-p2sh address: "+addr)
                        elif (coin_type==145) and (txin_type== 'p2pkh' or txin_type== 'p2sh'): # for bcash
                            addr= coin.scripttoaddr(script)
                            addr= convert.to_cash_address(addr) #cashAddr conversion
                            addr= addr.split(":",1)[-1] #remove prefix
                            Logger.debug("Satochip: txin type: "+ txin_type +" address: "+addr)
                        else:
                            addr= "unsupported script:"+script+"\n"
                        
                        txt+="input:\n"
                        txt+= "    "+"address: "+addr+" spent: "+str(txparser.inputAmountLong/100000)+"\n"  #satoshi to mBtc
                                                            
                       #parse outputs
                        outputs_hex= message['txo']
                        outputs= bytes.fromhex(outputs_hex)
                        hashOutputs=sha256(sha256(outputs[1:]).digest()).hexdigest()
                        outparser= TxParser(outputs)
                        while not outparser.is_parsed():
                            chunk= outparser.parse_outputs()
                        
                        nb_outs= outparser.txCurrentOutput
                        Logger.debug("Satochip: nbrOutputs: "+str(nb_outs))
                        txt+="nb_outputs: "+str(nb_outs) + "\n"
                        txt+="outputs:\n"
                        amnt_out=0
                        for i in range(nb_outs):
                            amnt= outparser.outAmounts[i]  
                            amnt_out+=amnt
                            script= outparser.outScripts[i].hex()
                            is_data_script=False
                            Logger.debug("Satochip: outScripts: "+script)
                            Logger.debug("Satochip: amount: "+str(amnt))
                            if script.startswith( '76a914' ):#p2pkh
                                addr= coin.scripttoaddr(script)
                            elif script.startswith( 'a914' ): #p2sh
                                addr= coin.scripttoaddr(script)
                            elif script.startswith( '0014' ):#p2wpkh
                                hash= bytes.fromhex(script[4:])
                                addr= coin.hash_to_segwit_addr(hash)
                            elif script.startswith( '0020' ): #p2wsh
                                hash= bytes.fromhex(script[4:])
                                addr= coin.hash_to_segwit_addr(hash)
                            elif script.startswith( '6a' ): # op_return data script  
                                addr= "DATA: "+bytes.fromhex(script[6:]).decode('utf-8')
                                is_data_script=True                            
                            else: 
                                addr= "unsupported script:"+script+"\n"
                                
                            if coin_type==145 and not is_data_script:
                                    addr= convert.to_cash_address(addr) #cashAddr conversion
                                    addr= addr.split(":",1)[-1] #remove prefix
                                
                            Logger.debug("Satochip: address: "+addr)
                            txt+= "    "+"address: "+addr+" spent: "+str(amnt/100000)+"\n"  #satoshi to mBtc
                        txt+= "    "+"total: "+str(amnt_out/100000)+" m"+coin.coin_symbol+"\n"  #satoshi to mBtc
                        
                        if hashOutputs!=txparser.hashOutputs.hex():
                            txt+= "Warning! inconsistent output hashes!\n"
                    
                    # non-segwit tx
                    else:
                        pre_tx_dic={}
                        try: 
                            pre_tx_dic= transaction.deserialize(pre_tx)
                        except Exception as e:
                            Logger.warning("Exception during (non-segwit) tx parsing: "+str(e))
                            txt="Error parsing tx!"
                            self.listener.clear(keyhash)
                            break
                        Logger.debug("Satochip: pre_tx_dic: "+str(pre_tx_dic))
                        
                        # inputs 
                        amount_in=0
                        ins= pre_tx_dic['ins']
                        nb_ins= len(ins)
                        txt+="nb_inputs: "+str(nb_ins) + "\n"
                        txt+="inputs:\n"
                        for i in ins:
                            script= i['script'].hex()
                            Logger.debug("Satochip: input script: "+script)
                            
                            # recover script and corresponding addresse
                            if script=="":# all input scripts are removed for signing except 1
                                outpoint= i['outpoint']
                                hash= outpoint['hash'].hex()
                                index= outpoint['index']
                                #Logger.debug('Satochip: hash: hash:index: ' +hash+":"+str(index))
                                tx= coin.fetchtx(hash)
                                #Logger.debug('Satochip: tx: '+str(tx))
                                outs= tx['out']
                                out= outs[index]
                                val= out['value']
                                script= out['script']
                                addr= coin.scripttoaddr(script)
                                addr= "(empty for signing: "+ addr[0:16] +"...)" 
                            if script.endswith("ae"):#m-of-n pay-to-multisig
                                m= int(script[0:2], 16)-80
                                n= int(script[-4:-2], 16)-80
                                txt+="    "+"multisig "+str(m)+"-of-"+str(n)+"\n"
                                addr= coin.p2sh_scriptaddr(script)
                                Logger.debug("Satochip: address multisig: "+addr)
                            else: #p2pkh, p2sh
                                addr= coin.scripttoaddr(script)
                                Logger.debug("Satochip: address: "+addr)
                            
                            # get value from blockchain explorer
                            val=0
                            try: 
                                unspent= coin.unspent_web(addr)
                                for d in unspent:
                                    val+=d['value']
                            except Exception as e:
                                Logger.warning("Exception during coin.unspent_web request: "+str(e))
                                #try to get value from electrum server (seem slow...)
                                # try:
                                    # hs= sha256(bytes.fromhex(script)).digest()
                                    # hs= hs[::-1]
                                    # balances=  coin.balance(True, hs.hex())
                                    # val= sum(balances)                                  
                                # except Exception as e:
                                    # Logger.warning("Exception during coin.balance request: "+str(e))                            
                            
                            txt+="    "+"address: "+addr+" balance: "+str(val/100000) +"\n" 
                            amount_in+=val
                        txt+="    "+"total: "+str(amount_in/100000)+" m"+coin.coin_symbol+"\n"  #satoshi to mBtc
                        
                        # outputs    
                        fee=0
                        amount_out=0
                        outs= pre_tx_dic['outs']
                        nb_outs= len(outs)
                        txt+="nb_outputs: "+str(nb_outs) + "\n"
                        txt+="outputs:\n"
                        for o in outs:
                            val= (o['value'])
                            script= o['script'].hex()
                            Logger.debug("Satochip: output script: "+script)
                            if script.startswith( '76a914' ):# p2pkh
                                addr= coin.scripttoaddr(script)
                            elif script.startswith( 'a914' ): # p2sh
                                addr= coin.scripttoaddr(script)
                            elif script.startswith( '0014' ):#p2wpkh
                                hash= bytes.fromhex(script[4:])
                                addr= coin.hash_to_segwit_addr(hash)
                            elif script.startswith( '0020' ):#p2wsh
                                hash= bytes.fromhex(script[4:])
                                addr= coin.hash_to_segwit_addr(hash)
                            else: 
                                addr= "unsupported script:"+script+"\n"
                            txt+="    "+"address: "+addr+" spent: "+str(val/100000)+"\n" #satoshi to mBtc
                            amount_out+=val
                        txt+="    "+"total: "+str(amount_out/100000)+" m"+coin.coin_symbol+"\n"  #satoshi to mBtc
                        fee= amount_in-amount_out
                        if fee >=0:
                            txt+="    "+"fees:  "+str(fee/100000)+" m"+coin.coin_symbol+"\n"  #satoshi to mBtc
                else: 
                    txt= "Unsupported operation: "+decrypted.decode('ascii')
                
                # 2FA challenges:
                # - Tx approval: [ 32b Tx hash | 32-bit 0x00-padding ]
                # - ECkey import:[ 32b coordx  | 32-bit (0x10^key_nb)-padding ]
                # - ECkey reset: [ 32b coordx  | 32-bit (0x20^key_nb)-padding ]
                # - 2FA reset:   [ 20b 2FA_ID  | 32-bit 0xAA-padding ]  
                # - Seed reset:  [ 32b authntikey-coordx  | 32-bit 0xFF-padding ]
                # - Msg signing: [ 32b SHA26(btcHeader+msg) | 32-bit 0xBB-padding ]
                self.listener.postbox.append([keyhash, challenge])
                self.display = txt
                self.label_logs+= txt +"\n"
                Logger.info("Satochip: \nNew challenge: "+challenge+"\nReceived on "+str(datetime.now())+":\n"+txt)
                
                self.btn_disabled= False
                break
    
    def scan_qr(self, on_complete):
        if platform != 'android':
            print("Qr code scanning is not supported!")
            save_popup = SaveDialog(self)
            save_popup.open()
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
        try: 
            secret_2FA= bytearray.fromhex(self.label_qr_data) #check if hex 
            self.myfactors.add_new_factor(self.label_qr_data, self.label_2FA_label)
            self.label_qr_data= "QR code added!"
            self.label_logs+= "Second factor added\nlabel: "+self.label_2FA_label+"\n"+LOG_SEP
            self.label_2FA_stored+= self.label_2FA_label+"\n"
            self.load_list_2FA()
        except ValueError:
            Logger.warning("Satochip: Error: the qr code should provide a hexadecimal value")
            self.label_qr_data= "Error: code should be a hexadecimal value"
            self.label_logs+= "Error: the qr code should provide a hexadecimal value"+"\n"+LOG_SEP
            
        self.btn_approve_qr_disabled=True
        
        
                                   
class TestApp(App):
    def build(self):
        self.title = 'Satochip 2-Factor Authentication App'
        root= Satochip()
        Clock.schedule_interval(root.update, 3.0)
        return root

# on platform where qr code scanning is not (yet) supported, it is possible to copy/paste the 2FA key via a popup windows...
class SaveDialog(Popup):

    def __init__(self,my_widget,**kwargs): 
        print("Debug in")
        super(SaveDialog,self).__init__(**kwargs)

        self.my_widget = my_widget
        
        #txt input
        self.content = BoxLayout(orientation="vertical")
        self.name_input = TextInput(text='enter 2FA key here...')
        
        #buttons
        self.content2 = BoxLayout(orientation="horizontal")
        self.save_button = Button(text='Save')
        self.save_button.bind(on_press=self.save)
        self.cancel_button = Button(text='Cancel')
        self.cancel_button.bind(on_press=self.cancel)
        self.content2.add_widget(self.save_button)
        self.content2.add_widget(self.cancel_button)
        
        self.content.add_widget(self.name_input)
        self.content.add_widget(self.content2)
         
    def save(self,*args):
        print("save 2FA")
        self.my_widget.label_qr_data= self.name_input.text
        self.my_widget.btn_approve_qr_disabled=False
        self.dismiss()

    def cancel(self,*args):
        print("cancel 2FA")
        self.dismiss()


if __name__ == '__main__':
    TestApp().run()