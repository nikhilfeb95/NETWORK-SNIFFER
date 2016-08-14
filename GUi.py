import os

__author__ = 'NIKHIL'

from tkinter import *
import socket
import tkMessageBox
import tkSimpleDialog

def onpress():
    os.system('python sniffer.py')
def getip():
    input = entry1.get()
    out = socket.gethostbyname('%s' %input )
    tkMessageBox.showinfo("RESULT",out)


root = Tk()
label1 = Label(root, text = "SNIFF THE NETWORK",fg = "green",bg = "black")
label1.grid(row =0,columnspan =4)
button1 = Button(text="SNIFF",command = onpress)
button1.grid(row=1,column = 0,sticky = E)
label2 = Label(root,text = "GET IP OF THE URL")
label2.grid(row=2)
entry1 = Entry(root)
entry1.grid(row=2,column=1)
button2 = Button(text = "GET IP",command = getip)
button2.bind('<Button-1>')
button2.grid(columnspan = 2)
root.mainloop()