import tkinter as tk
import os
from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPBindError
import datetime
import socket

LDAP_SEACRCH_BASE_DIR = "OU=Кластер Західний,OU=Агропідприємства,OU=Компютери,OU=Kernel Holding,DC=kernel,DC=local"

def CheckNetwork():
    try:
        hostname, domain = socket.gethostbyaddr("10.1.249.117")[0].partition('.')[::2]
    except socket.herror:     
        WriteToLog("No connection to domain network")
        TextBoxUserContext.insert(0, "No connection to domain network")
        TextBoxDomainComputerName.insert("1.0", "No connection to domain network")
        TextBoxDomainComputerRML.insert("1.0", "No connection to domain network")

        TextBoxUserContext.configure(state="disabled")
        TextBoxPasswordContext.configure(state="disabled")
        TextBoxDomainComputerName.configure(state="disabled")
        TextBoxDomainComputerRML.configure(state="disabled")
        print(socket.herror)
    else:
        WriteToLog("Successfully connected to {0}".format(hostname + "." + domain))


def WriteToLog(Text):
    TIME = datetime.datetime.now()
    FILE_PATH = os.getenv("USERPROFILE") + "\\LAPyS Log\\Log.log"
    with open(FILE_PATH, "a") as LogFile:
        LogFile.write(str(TIME) + ": " + Text + "\n")

def Encrypt(String):
    lst = list()
    for symbol in String:
        lst.append(ord(symbol))
    return lst

def Decrypt(ByteList):
    st = str()
    print("+++++++++++++++++++++++++++++++++++++++++++++++",type(ByteList))
    for ASCII_Code in ByteList:
        st += chr(int(ASCII_Code))
    return st


def get_ldap_info(UserName, PasswordLocal, ComName):
    ####! Debug info !####
    #print("Connection attempt")
    #print(UserName[0:])
    #print(PasswordLocal)
    #print(ComName)
    try:
        with Connection(Server("10.1.249.117", port=389, use_ssl=False), auto_bind=AUTO_BIND_NO_TLS, user="Kernel\\{0}".format(UserName), password=PasswordLocal) as c:
            c.search(search_base=LDAP_SEACRCH_BASE_DIR, search_filter="(&(objectCategory=computer)(objectClass=computer)(cn={0}))".format(ComName), search_scope=SUBTREE, attributes=["name", "ms-Mcs-AdmPwd"], get_operational_attributes=True)
        return c.entries
    except LDAPBindError:
        WriteToLog("Invalid LDAP credentials")
        TextBoxUserContext.insert(0, "Invalid LDAP credentials")
        TextBoxPasswordContext.insert(0, "Invalid LDAP credentials")
    else:
        WriteToLog("LDAP credential successfully accepted")
        

window = tk.Tk()

try:
    os.mkdir(os.getenv("USERPROFILE") + "\\LAPyS Log")
except FileExistsError:
    print("File already exists")

def Load(Event):
    BtnSave.configure(state="disabled")
    FILE_PATH = os.getenv("USERPROFILE") + "\\Credential.cred"
    with open(FILE_PATH, "r") as Cred:
        DECODED_NAME = Cred.readlines(1)
        DECODED_PASSW = Cred.readlines(1)
        TextBoxUserContext.insert(0, Decrypt(DECODED_NAME[0].split(",")))
        TextBoxPasswordContext.insert(0, Decrypt(DECODED_PASSW[0].split(",")))
        WriteToLog("Profile loaded from file Credential.cred")
    TextBoxUserContext.configure(state="disabled")
    TextBoxPasswordContext.configure(state="disabled")
    
def Save(Event):
    BtnLoad.configure(state="disabled")
    FILE_PATH = os.getenv("USERPROFILE") + "\\Credential.cred"
    with open(FILE_PATH, "w") as Cred:
        ENCODED_NAME = Encrypt(TextBoxUserContext.get())#TextBoxUserContext.get("1.0", "end-1c"))
        ENCODED_PASSW = Encrypt(TextBoxPasswordContext.get())#TextBoxPasswordContext.get("1.0", "end-1c"))
        Cred.write(str(ENCODED_NAME)[1:len(str(ENCODED_NAME))-1] + "\n" + str(ENCODED_PASSW)[1:len(str(ENCODED_PASSW))-1])
        WriteToLog("Profile saved from entry fields")
    TextBoxUserContext.configure(state="disabled")
    TextBoxPasswordContext.configure(state="disabled")

def GetPassword(Event):
    TextBoxDomainComputerRML.delete(1.0, "end")
    #FILE_PATH = os.getenv("USERPROFILE") + "\\Credential.cred"
    #with open(FILE_PATH, "r") as Cred:
        #DECODED_NAME = Cred.readlines(1)
        #DECODED_PASSW = Cred.readlines(1)
    UserContextLocal = TextBoxUserContext.get()#TextBoxUserContext.get("1.0", "end-1c") #Decrypt(DECODED_NAME[0].split(","))
    PasswordContextLocal = TextBoxPasswordContext.get()#TextBoxPasswordContext.get("1.0", "end-1c") #Decrypt(DECODED_PASSW[0].split(","))

    RequestedNameLocal = TextBoxDomainComputerName.get("1.0", "end-1c")

    if len(RequestedNameLocal) == 1:
        TextBoxDomainComputerRML.insert(1.0, "Requested name is empty!")

    AD = get_ldap_info(UserContextLocal, PasswordContextLocal, RequestedNameLocal)
    AD_Computers = dict()
    for obj in AD:
	    AD_Computers[(str(obj.entry_attributes_as_dict["name"])[2:len(str(obj.entry_attributes_as_dict["name"]))-2])] = str(obj.entry_attributes_as_dict["ms-Mcs-AdmPwd"])[2:len(str(obj.entry_attributes_as_dict["ms-Mcs-AdmPwd"]))-2]
    
    try:
        TextBoxDomainComputerRML.insert(1.0, AD_Computers[RequestedNameLocal])
    except KeyError:
        WriteToLog("No such name in OU. Requested {0}".format(TextBoxDomainComputerName.get("1.0", "end-1c")))
        TextBoxDomainComputerRML.insert(1.0, "No such name in OU")


window.geometry('400x180+100+100')

window.title("LAPyS")

labelUserLogin = tk.Label(text="Enter your domain login:")
labelUserLogin.place(x = 100, y = 5, width = 250, height = 15)

TextBoxUserContext = tk.Entry()
TextBoxUserContext.place(x = 100, y = 25, width = 250, height = 20)

#TextBoxUserContext = tk.Text()                                         # Поле ввода логина админа
#TextBoxUserContext.bind("<Key>")#, lambda a: "break") # Раскомментить чтобы запретить ввод
#TextBoxUserContext.place(x = 100, y = 25, width = 250, height = 20)

labelUserPassword = tk.Label(text="Enter your password:")
labelUserPassword.place(x = 100, y = 45, width = 250, height = 20)

TextBoxPasswordContext = tk.Entry()
TextBoxPasswordContext["show"] = "*"
TextBoxPasswordContext.place(x = 100, y = 65, width = 250, height = 20)

#TextBoxPasswordContext = tk.Text()                                         # Поле ввода пароля админа
#TextBoxPasswordContext.bind("<Key>")#, lambda a: "break") # Раскомментить чтобы запретить ввод
#TextBoxPasswordContext.place(x = 100, y = 65, width = 250, height = 20)

labelRequestedName = tk.Label(text="Enter name of computer:")
labelRequestedName.place(x = 100, y = 85, width = 250, height = 20)


TextBoxDomainComputerName = tk.Text()
TextBoxDomainComputerName.bind("<Key>")#, lambda a: "break")
TextBoxDomainComputerName.place(x = 100, y = 105, width = 250, height = 20)

TextBoxDomainComputerRML = tk.Text()
TextBoxDomainComputerRML.bind("<Key>", lambda a: "break")
TextBoxDomainComputerRML.place(x = 100, y = 145, width = 250, height = 20)

BtnLoad = tk.Button(window, text="Load", width=10, height=2, bg="white", fg="black")
BtnLoad.bind("<Button-1>", Load)
BtnLoad.place(x = 10, y = 25, width = 80, height = 20)

BtnSave = tk.Button(window, text="Save", width=10, height=2, bg="white", fg="black")
BtnSave.bind("<Button-1>", Save)
BtnSave.place(x = 10, y = 65, width = 80, height = 20)

BtnPassw = tk.Button(window, text="Get password", width=10, height=2, bg="white", fg="black")
BtnPassw.bind("<Button-1>", GetPassword)
BtnPassw.place(x = 10, y = 105, width = 80, height = 20)

CheckNetwork()

window.mainloop()