#-*-coding:utf-8-*-
#author:lukas

import tornado.web
import tornado.ioloop
from tornado.options import define,options,parse_command_line
import masscan
import requests
import pymongo
from bson.objectid import ObjectId
import nmap

define('port',default=8888,help='run on the port',type=int)
uri='/doc/page/login.asp'
temp_result_list=[]
#database=torndb.Connection('localhost','talk',user='root',password='123456')
l=[]
class MainHandler(tornado.web.RequestHandler):
  def get(self):
    self.render('example.html',title='professional scan',items=l,resultpage='')
  def post(self):
    count=1
    #print(self.request.remote_ip)
    ip=self.get_argument('ip')
    port=self.get_argument('port')
    mode=self.get_argument('mode')
    print mode
    if mode == 'masscan':
        if port == '80':
            l.append(ip)
            print l
            target=l
            instance_scan=scan()
            result=instance_scan.main_reqzwei(target.pop(),port)
            print type(result)
            #kkk=str(l)+str(result)
            self.render('example.html',title='professional scan',items=temp_result_list,resultpage='')
        else:
            l.append(ip)
            print l
            target=l
            instance_scan=scan()
            result=instance_scan.main_reqzwei_add_port(target.pop(),port)
            self.render('example.html',title='professional scan',items=temp_result_list,resultpage='')
    elif mode == 'pynmap':
        instance_scan=scan()
        temp=instance_scan.pynmap_main(ip,port)
        #print '<><><><><><><><><><><><<<>><><><><><><><><><><><><><><>'
        print temp







        self.render('example.html',title='professional scan',items='',resultpage=temp)




class scan:

  default_port='80'
  def masscan_main(self,target,port):
    default_port='80'
    if port=='':
      port=default_port
    mas = masscan.PortScanner()
    try:
      mas.scan(target, ports=port)
      big_result=mas.scan_result
      middle_result=big_result.get('scan')
      key=middle_result.keys()
      #print middle_result
      print key
      if key == '':
        print 'not found'
      return key
    except Exception as e:
      print e

  def pynmap_main(self,target,port):
    try:
        result_content=[]
        ip_address=target
        #port='1-1024'
        nm=nmap.PortScanner()
        #result=nm.scan(ip_address,port)
        temp_arguments='-p'+port+' '+'-sV'
        print temp_arguments
        result=nm.scan(hosts=ip_address, arguments=temp_arguments)#'-p80 -sV'
        print nm.command_line()
        val=result['scan'].values()
        #print val
        firstkey=result['scan'].keys()
        print firstkey
        for ip in firstkey:
            result_content.append(result['scan'][ip])
            #print result['scan'][ip]
            #print result_content

        print result_content
        return result_content




    except Exception as e:
        print e


  def req(self,target,uri):

    headers={
    'Cache-Control' : 'max-age=0',
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36',
    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language' : 'en-US,en;q=0.9'
    }
    url='http://'+target+uri
    print url
    result=requests.get(url,headers=headers,stream=True,timeout=3)
    #head=result.headers
    #print result.status_code
    code=result.status_code
    if str(code) == '200':
      print 'we have got a web_cam:'+target
      self.target_adder(target)

  def reqzwei(self,target,port):
    headers={
    'Cache-Control' : 'max-age=0',
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36',
    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language' : 'en-US,en;q=0.9'
    }
    url='http://'+target
    print url
    result=requests.get(url,headers=headers,stream=True,timeout=3)
    head=result.headers
    server=head.get('server')
    print server
    product_list=self.product_type_relation()
    if server in product_list:
      self.target_adder(target)
      print 'we have a web_cam:'+target

  def reqzwei_add_port(self,target,port):
    headers={
    'Cache-Control' : 'max-age=0',
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36',
    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language' : 'en-US,en;q=0.9'
    }
    url='http://'+target+':'+port
    print url
    result=requests.get(url,headers=headers,stream=True,timeout=3)
    head=result.headers
    server=head.get('server')
    print server
    product_list=self.product_type_relation()
    if server in product_list:
      self.target_adder(target)
      print 'we have a web_cam:'+target

  def target_adder(self,target):
    final=temp_result_list.append(target)
    #return final

  def data_log_output(self):

    print temp_result_list
    return temp_result_list

  def product_type_relation(self):
    type_uri_dict={
    'hikvision':'/doc/page/login.asp'

    }
    type_head_dict={
    'netwave':['Netwave','Netwave IP Camera'],
    'hikvision':['Hikvision-Webs','DVRDVS-Webs','DNVRS-Webs']

    }
    print type_head_dict['hikvision']
    hikvision_list=type_head_dict.get('hikvision')

    return hikvision_list

  def main_req(self,target,port):
    if port=='':
      port=default_port
    masscan_list=self.masscan_main(target,port)
    for ip in masscan_list:
      one=masscan_list.pop()
      try:
        print ip
        self.req(one,uri)
        self.data_log_output()
      except Exception as e:
        print e

    print 'camera found:'+str(temp_result_list)

  def main_reqzwei(self,target,port):
    if port=='':
      port=default_port
    masscan_list=self.masscan_main(target,port)
    for ip in masscan_list:
      one=masscan_list.pop()
      try:
        print ip
        self.reqzwei(one,port)
        self.data_log_output()
      except Exception as e:
        print e

  def main_reqzwei_add_port(self,target,port):
    if port=='':
        port=default_port
    masscan_list=self.masscan_main(target,port)
    for ip in masscan_list:
        one=masscan_list.pop()
        try:
            print ip
            self.reqzwei_add_port(one,port)
            self.data_log_output()
        except Exception as e:
            print e


    print 'camera found:'+str(temp_result_list)






def main():
  parse_command_line()
  app=tornado.web.Application([(r'/',MainHandler),
    ],)
  app.listen(options.port)
  print 'now listening on port 8888'
  tornado.ioloop.IOLoop.instance().start()

if __name__=='__main__':
  main()