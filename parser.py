import ijson 
import maxminddb

#with open('Packets_for_practice2.json', 'r') as file:
   # packets_info = ujson.lazy_loads(file)
class Maxinddb:
    ASN_path = 'GeoLite2-ASN.mmdb'
    CITY_path = 'GeoLite2-City.mmdb'
    Country_path = 'GeoLite2-Country.mmdb'

    def __init__(self):
        self.ASN_Reader = self.__read_file(self.ASN_path)
        self.CITY_Reader = self.__read_file(self.CITY_path)
        self.Country_Reader = self.__read_file(self.Country_path)

    def __read_file(self, file):
        return maxminddb.open_database(file)
    
    def get_ASN_from_ip(self, ip_addr):
        return self.ASN_Reader.get(ip_addr)
    
    def get_CITY_from_ip(self, ip_addr):
        return self.CITY_Reader.get(ip_addr)
    
    def get_Country_from_ip(self, ip_addr):
        return self.Country_Reader.get(ip_addr)
'''class Maxinddb_mixin:
    def __init__(self):
        self.Mixindvb = Maxinddb()
        pass

    def enrich_data(self, data):'''



class Parser:
    def __init__(self, file):
        self.file = file
        self.Packet_data = []
        self.__open_file()
        self.__calculate_total_len()
        self.Mixindvb = Maxinddb()
        self.__enrich_data()
       
    def __open_file(self):
        with open(f'{self.file}', 'r') as file:
            self.packets_info = ijson.parse(file)
            self.__split_info()
    
    def __split_info(self):
         counter = 1
         for prefix, event, value in self.packets_info:
            if prefix == 'item._index': 
                if counter != 1:
                    self.Packet_data.append(temp)
                temp = {'index': None, 'frame_protocols': None, 'frame_len':None, 'ip_src':None, 'ip_dst': None, 'tcp_srcport':None, 'tcp_dstport':None}
                temp['index'] = f'{value}_{counter}'
                counter+=1
            elif prefix == 'item._source.layers.frame.frame.protocols':
                temp['frame_protocols'] = value
            elif prefix == 'item._source.layers.frame.frame.len':
                temp['frame_len'] = int(value)
            elif prefix == 'item._source.layers.ip.ip.src':
                temp['ip_src'] = value
            elif prefix == 'item._source.layers.ip.ip.dst':
               temp['ip_dst'] = value 
            elif prefix == 'item._source.layers.tcp.tcp.srcport':
                temp['tcp_srcport'] = value 
            elif prefix == 'item._source.layers.tcp.tcp.dstport':
                temp['tcp_dstport'] = value
                #print(temp)
    
    def __enrich_data(self):
        for item in self.Packet_data:
            if item['ip_src'] != None:
                item['ip_src_asn'] = self.Mixindvb.get_ASN_from_ip(item['ip_src'])
                try:
                    item['ip_src_city'] = self.Mixindvb.get_CITY_from_ip(item['ip_src'])['city']['names']['en']
                except TypeError :
                    item['ip_src_city'] = None
                except KeyError:
                    item['ip_src_city'] = None

                try:
                    item['ip_src_country'] = self.Mixindvb.get_Country_from_ip(item['ip_src'])['country']['names']['en']
                except TypeError:
                     item['ip_src_country'] = None
                except KeyError:
                     item['ip_src_country'] = None     

            else:
                item['ip_src_asn'] = None
                item['ip_src_city'] = None
                item['ip_src_country'] = None

            if item['ip_dst'] != None:  
                item['ip_dst_asn'] = self.Mixindvb.get_ASN_from_ip(item['ip_dst'])
                try:
                    item['ip_dst_city'] = self.Mixindvb.get_CITY_from_ip(item['ip_dst'])['city']['names']['en']
                except TypeError:
                     item['ip_dst_city'] = None
                except KeyError:
                     item['ip_dst_city'] = None
                try:
                    item['ip_dst_country'] = self.Mixindvb.get_Country_from_ip(item['ip_dst'])['country']['names']['en']
                except TypeError:
                     item['ip_dst_country'] = None
                except KeyError:
                     item['ip_dst_country'] = None
                     
            else:
                item['ip_dst_asn'] = None
                item['ip_dst_asn'] = None
                item['ip_dst_asn'] = None

    def get_ip(self):
        for i in self.Packet_data:
            print(i['ip_src'])
    def get_total_len(self):
        return self.total_len

    def __calculate_total_len(self):
        self.total_len = 0
        for item in self.Packet_data:
            self.total_len+=item['frame_len']

    def print_parsed_info(self):
        for item in self.Packet_data:
            print(item)
    def get_parsed_info(self):
        return self.Packet_data

object = Parser('Packets_for_practice2.json')

object.print_parsed_info()
#a = Maxinddb()
#print(a.get_CITY_from_ip('192.168.86.214')['city']['names'])

#data = packets_info[0]
#print(data['_index'])
#print(data['_source']['layers']['frame'])
