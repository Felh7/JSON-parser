import ijson 
import maxminddb
import psycopg2

#with open('Packets_for_practice2.json', 'r') as file:
   # packets_info = ujson.lazy_loads(file)
class PSQLConnection:
    def __init__(self, connect_data: dict):
        self.connection = psycopg2.connect(
            host=connect_data['host'],
            user=connect_data['user'],
            password=connect_data['password'],
            database=connect_data['database']
        )
        self.cursor = self.connection.cursor()

    def psql_insert(self, table, fields , values):
        self.cursor.execute(f"INSERT INTO {table} ({fields}) VALUES ({','.join(['%s']*len(values))})", values)
        self.connection.commit()

    def psql_update(self, table, new_value):
        self.cursor.execute(f"UPDATE {table} SET {new_value} WHERE")
        self.connection.commit()

    def psql_delete(self, table, condition):
        self.cursor.execute(f"DELETE FROM {table} WHERE {condition}")
        self.connection.commit()

    def psql_select(self, table, values):
        self.cursor.execute(f"SELECT {values} FROM {table}")
        self.connection.commit()



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
        self.__calculate_total_len
       
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
                temp = {'index': '', 'frame_protocols': '', 'frame_len':'', 'ip_src':'', 'ip_dst': '', 'tcp_srcport':'', 'tcp_dstport':''}
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
            if item['ip_src'] != '':
                try:
                    item['ip_src_asn'] = self.Mixindvb.get_ASN_from_ip(item['ip_src'])['autonomous_system_organization']
                except TypeError:
                    item['ip_src_asn'] = ''
                except KeyError:
                    item['ip_src_asn'] = ''

                try:
                    item['ip_src_city'] = self.Mixindvb.get_CITY_from_ip(item['ip_src'])['city']['names']['en']
                except TypeError :
                    item['ip_src_city'] = ''
                except KeyError:
                    item['ip_src_city'] = ''

                try:
                    item['ip_src_country'] = self.Mixindvb.get_Country_from_ip(item['ip_src'])['country']['names']['en']
                except TypeError:
                     item['ip_src_country'] = ''
                except KeyError:
                     item['ip_src_country'] = ''     

            else:
                item['ip_src_asn'] = ''
                item['ip_src_city'] = ''
                item['ip_src_country'] = ''

            if item['ip_dst'] != '': 
                try:
                    item['ip_dst_asn'] = self.Mixindvb.get_ASN_from_ip(item['ip_dst'])['autonomous_system_organization']
                except KeyError: 
                     item['ip_dst_asn'] = ''
                except TypeError:
                     item['ip_dst_asn'] = '' 

                try:
                    item['ip_dst_city'] = self.Mixindvb.get_CITY_from_ip(item['ip_dst'])['city']['names']['en']
                except TypeError:
                     item['ip_dst_city'] = ''
                except KeyError:
                     item['ip_dst_city'] = ''

                try:
                    item['ip_dst_country'] = self.Mixindvb.get_Country_from_ip(item['ip_dst'])['country']['names']['en']
                except TypeError:
                     item['ip_dst_country'] = ''
                except KeyError:
                     item['ip_dst_country'] = ''
                     
            else:
                item['ip_dst_asn'] = ''
                item['ip_src_city'] = ''
                item['ip_src_country'] = ''

    def get_total_len(self):
        return self.total_len

    def __calculate_total_len(self):
        self.total_len = 0
        for item in self.Packet_data:
            self.total_len+=item['frame_len']
        
    def get_total_len(self):
        return self.total_len

    def print_parsed_info(self):
        for item in self.Packet_data:
            print(item)

    def get_parsed_info(self):
        return self.Packet_data
    
    def get_list_info_by_indx(self, index):
        temp_tupl= ()
        temp_tupl += (self.get_parsed_info()[index]['ip_src_country'],)
        try:
            temp_tupl += (self.get_parsed_info()[index]['ip_dst_country'],)
        except KeyError:
             temp_tupl += ('',) 
        try:
            temp_tupl += (int(self.get_parsed_info()[index]['tcp_srcport']),)
        except ValueError:
            temp_tupl += (None,)
        try:
            temp_tupl += (int(self.get_parsed_info()[index]['tcp_dstport']),)
        except ValueError:
            temp_tupl += (None,)
        temp_tupl += (self.get_total_len(),)
        temp_tupl += (self.get_parsed_info()[index]['ip_src_city'],)
        try:
            temp_tupl += (self.get_parsed_info()[index]['ip_dst_city'],)
        except KeyError:
             temp_tupl += ('',)
        temp_tupl += (self.get_parsed_info()[index]['ip_src_asn'],)
        temp_tupl += (self.get_parsed_info()[index]['ip_dst_asn'],)
        temp_tupl += (str(self.get_parsed_info()[index]['frame_protocols'][-3:]),)
        
        if self.get_parsed_info()[index]['ip_src'] != '':
            temp_tupl += (self.get_parsed_info()[index]['ip_src'],)
        else:
            temp_tupl += (None,)
        if self.get_parsed_info()[index]['ip_dst'] != '':
            temp_tupl += (self.get_parsed_info()[index]['ip_dst'],)
        else:
            temp_tupl += (None,)

        return temp_tupl
    
    def get_length_of_data(self):
        return len(self.get_parsed_info())


PARSER = Parser('Packets_for_practice2.json')
#PARSER.print_parsed_info()

psql_connect_data = {
    'host': 'localhost',
    'user': 'nikita',
    'password': '',
    'database': 'ip_info_02'
}

PSQL_CONNCT = PSQLConnection(psql_connect_data)

fields_to_insert = ('country_from_02', 'country_to_02', 'port_src_02', 'port_dst_02', 'packet_size_02', 'city_from_02', 'city_to_02', 'ASN_from_02', 'ASN_to_02','protocol_02','ip_src_02', 'ip_dst_02')
column_names_str = ", ".join(fields_to_insert)
for i in range(PARSER.get_length_of_data()):
    values_to_insert = PARSER.get_list_info_by_indx(i)
    PSQL_CONNCT.psql_insert('packets', column_names_str, values_to_insert)


#a = Maxinddb()
#print(a.get_CITY_from_ip('192.168.86.214')['city']['names'])

#data = packets_info[0]
#print(data['_index'])
#print(data['_source']['layers']['frame'])
