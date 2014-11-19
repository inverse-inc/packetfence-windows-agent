import wx
import parse
from imageBG import bgimg
 
########################################################################
class MainPanel(wx.Panel):

	def OnClose(self, e):
		parse.parsing()        
		
	def __init__(self, parent):
		wx.Panel.__init__(self, parent=parent)
		self.frame = parent
 
		sizer = wx.BoxSizer(wx.VERTICAL)
		hSizer = wx.BoxSizer(wx.HORIZONTAL)
 
		cbtn = wx.Button(self, label='Configure', pos=(196, 144))
		cbtn.Bind(wx.EVT_BUTTON, self.OnClose)
		
		self.SetSizer(hSizer)
		self.Bind(wx.EVT_ERASE_BACKGROUND, self.OnEraseBackground)
 
	def OnEraseBackground(self, evt):
		"""
		BackgroundImage
		"""
		dc = evt.GetDC()
 
		if not dc:
			dc = wx.ClientDC(self)
			rect = self.GetUpdateRegion().GetBox()
			dc.SetClippingRect(rect)
		dc.Clear()
		img = bgimg.GetImage()
		bmp = img.ConvertToBitmap()
		dc.DrawBitmap(bmp, 0, 0)
 
 
########################################################################
class MainFrame(wx.Frame):
 
	def __init__(self):
		"""Constructor"""
		wx.Frame.__init__(self, None, size=(480,318))
		panel = MainPanel(self)        
		self.Center()
 
########################################################################
class Main(wx.App):
 
	def __init__(self, redirect=False, filename=None):
		"""Constructor"""
		wx.App.__init__(self, redirect, filename)
		dlg = MainFrame()
		dlg.Show()

if __name__ == "__main__":
	app = Main()
	app.MainLoop()


#  Copyright (C) 2005-2014 Inverse inc.
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
#  USA.
