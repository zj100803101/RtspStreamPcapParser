from cmath import log
from os import startfile
import struct
import io
import argparse
import sys
import logging
from tracemalloc import start
from turtle import left
sys.path.append('TcpData.py')
from TcpData import TcpData

logger = logging.getLogger('test_logger')
logger.setLevel(logging.INFO)
test_log = logging.FileHandler('test.log','a',encoding='utf-8')
# 向文件输出的日志级别
test_log.setLevel(logging.INFO)
# 向文件输出的日志信息格式
formatter = logging.Formatter('%(asctime)s - %(filename)s - line:%(lineno)d - %(levelname)s - %(message)s -%(process)s')
test_log.setFormatter(formatter) 
# 加载文件到logger对象中
logger.addHandler(test_log)

class AnalysisPcap(object):

    def __init__(self, pcap_file, out_file):
        self.pcap_file = pcap_file
        self.out_file = out_file
        self.video_frames = 0
        self.audio_frames = 0
        self.drop_vframes = 0
        self.vframe_seq = 0
        self.stream_flow = 0
        self.data_content = ''
        self.left_packet = ''

    @staticmethod
    def is_ipv4_tcp(data):
        """传入数据帧，对数据帧的以太网层的type字段以及ip的protocol字段进行判断，若为IPV4下的tcp协议

        返回TRUE，反之则为FALSE"""
        return struct.unpack('H', data[12:14])[0] == 8 and data[23] == 6

    def print_hex(bytes):
        l = [hex(int(i)) for i in bytes]
        print(" ".join(l))

    def print_bytes_hex(data):
        l = ['%02X' % i for i in data]
        print(" ".join(l))

    def print_string_hex(data):
        l = ['%02X' % ord(i) for i in data]
        print(" ".join(l))

    def parseRtspData(self, content):
        len_content = len(content)
        if 0 == len_content:
            #logger.error("empty packet!")
            return
        # rtsp信令不处理, 保证只有码流被处理
        if (-1 != content.find(b'RTSP')) or (-1 != content.find(b'rtsp')):
            logger.warning("not save rtsp msg:%s" % (content))
            return        
        
        head_4bytes = ''.join([hex(i) for i in content[0:12]])
        flag = struct.unpack('!B', content[0:1])[0]
        ftype = struct.unpack('!B', content[1:2])[0]
        rtp_len = struct.unpack('!H', content[2:4])[0]        
        rtp_seq = struct.unpack('!H', content[6:8])[0]
        pp = ['%02X' % i for i in content]
        copmlete_packet = "".join(pp)       
        print("head:%s video:%d audio:%d flag:%x type:%x pkg:%d %x seq:%d" % (head_4bytes, self.video_frames, self.audio_frames, flag, ftype, rtp_len, rtp_len, rtp_seq))        
        logger.info("head:%s len:%d_%d video:%d audio:%d flag:%x type:%x rtp:%d %x seq:%d flow:%d len:%d" % (head_4bytes, len(head_4bytes), len(content), self.video_frames, 
                    self.audio_frames, flag, ftype, rtp_len, rtp_len, rtp_seq, self.stream_flow, len(self.data_content)))     
        logger.info("".join(pp))
        # 若首字节不是0x24说明这个包属于上个粘包剩余部分数据, 需要将这个包附加到left_packet
        if 0x24 != flag:
            self.left_packet += "".join(pp)
            logger.warning("recv part data,len:%d content:%s" % (len_content, copmlete_packet))
            return
        
        # 首字节为0x24说明之前的粘包已全部收齐, 若存在历史粘包数据则先将粘包数据转移到data_content上
        len_left_content = len(self.left_packet)
        if len_left_content > 0 :
            index = 0
            left_head_4bytes = self.left_packet[0:24]
            left_flag = int(self.left_packet[index:index+2], 16)
            left_ftype = int(self.left_packet[index+2:index+4], 16)
            left_rtp_len = int(self.left_packet[index+4:index+8], 16)        
            left_rtp_seq = int(self.left_packet[index+12:index+16], 16)
            self.data_content += self.left_packet
            logger.info("add left packet to main,len:%d %d head:%s flag:%x type:%x rtp:%d %x seq:%d" % (len(self.data_content), len_left_content,
                            left_head_4bytes, left_flag, left_ftype, left_rtp_len, left_rtp_len, left_rtp_seq))           
            # 统计粘包帧信息
            if 0x0 == left_ftype :
                self.video_frames += 1
                drop_frame_num = left_rtp_seq - self.vframe_seq - 1
                if drop_frame_num > 0 and self.vframe_seq > 0 :
                    self.drop_vframes += drop_frame_num
                    print("WARN! drop left video frame nums:%d,cur:%d last:%d" % (drop_frame_num, rtp_seq, self.vframe_seq))
                    logger.warning("WARN! drop left video frame nums:%d,cur:%d last:%d" % (drop_frame_num, rtp_seq, self.vframe_seq))
                self.vframe_seq = left_rtp_seq 
            elif 0x2 == left_ftype :
                self.audio_frames += 1
            self.stream_flow += len_left_content
            self.left_packet = ''

        # 先将前面完整的rtp包转移到data_content
        self.data_content += copmlete_packet[0:(rtp_len+4)*2]
        # 若rtp长度+4字节rtptcp长度小于包长度说明存在粘包, 需要将不完整的数据保存到left
        if rtp_len + 4 < len_content:
            self.left_packet += copmlete_packet[(rtp_len+4)*2:] 
            logger.info("save left part packet:%s" % (self.left_packet))           

        # 音视频帧信息统计
        if 0x0 == ftype :
            self.video_frames += 1
            drop_frame_num = rtp_seq - self.vframe_seq - 1
            if drop_frame_num > 0 and self.vframe_seq > 0 :
                self.drop_vframes += drop_frame_num
                print("WARN! drop video frame nums:%d,cur:%d last:%d" % (drop_frame_num, rtp_seq, self.vframe_seq))
                logger.warning("WARN! drop video frame nums:%d,cur:%d last:%d" % (drop_frame_num, rtp_seq, self.vframe_seq))
            self.vframe_seq = rtp_seq 
        elif 0x2 == ftype :
            self.audio_frames += 1

        self.stream_flow += (rtp_len+4)*2
        return

    def parseRtspDataV2(self, content):
        if 0 == len(content):
            return
        head_4bytes_content = ' '.join([hex(i) for i in content[0:8]])
        first_bytes_data = head_4bytes_content[0:4]
        second_bytes_data = head_4bytes_content[5:8]
        interleaved_type = struct.unpack('!B', content[1:2])[0]
        rtp_seq = struct.unpack('!H', content[6:8])[0]
        if "0x24" != first_bytes_data:
            return
        if "0x0" == second_bytes_data :
            self.video_frames += 1
        elif "0x2" == second_bytes_data :
            self.audio_frames += 1
        print(head_4bytes_content, len(head_4bytes_content), first_bytes_data, second_bytes_data, interleaved_type, rtp_seq, "video:%d audio:%d" % (self.video_frames, self.audio_frames))        
        return

    # @staticmethod
    def get_tcp_data(self, data):
        """传入数据帧，对数据帧的Tcp中的 src, dst,src_port,dst_port, seq, ack, flags, content

        返回该tcp数据列表"""
        ip_header_len = (data[14] & 0x0F) * 4
        ip_total_len = struct.unpack('!H', data[16: 18])[0]
        # 26=以太网协议14字节+IP协议前12字节
        src_ip = '.'.join([str(i) for i in data[26:30]])
        # 30=以太网协议14字节+IP协议前12字节+src_ip的4字节
        dst_ip = '.'.join([str(i) for i in data[30:34]])
        src_port = struct.unpack(
            '!H', data[14 + ip_header_len:14 + ip_header_len + 2])[0]
        dst_port = struct.unpack(
            '!H', data[14 + ip_header_len + 2:14 + ip_header_len + 4])[0]
        seq = struct.unpack(
            '!I', data[14 + ip_header_len + 4:14 + ip_header_len + 8])[0]
        ack = struct.unpack(
            '!I', data[14 + ip_header_len + 8:14 + ip_header_len + 12])[0]
        flags = data[14 + ip_header_len + 13]
        tcp_header_len = (data[14 + ip_header_len + 12] >> 4) * 4
        tcontent = data[14 + ip_header_len + tcp_header_len:14 + ip_total_len]
        #head_4bytes_content = ' '.join([hex(i) for i in tcontent[0:4]])
        self.parseRtspData(tcontent)
        #print(ip_header_len,ip_total_len,tcp_header_len,src_port,dst_ip,dst_port,seq)
        return [src_ip, dst_ip, src_port, dst_port, seq, ack, flags, tcontent]

    def dump_tcp_content(self):
        """传入pcap文件，导出 PCAP 文件中的 TCP 内容

        返回包含所有 TCP 内容的数组"""
        open_file = open(self.pcap_file, 'rb')
        file_length = int(open_file.seek(0, io.SEEK_END))
        print("open pcap file size: ", file_length)
        logger.info("open pcap file size: %d" % (file_length))
        open_file.seek(24)
        pcap_header = 24
        tcp_stream = []
        while pcap_header < file_length:
            # Packet header, len=16
            open_file.seek(8, io.SEEK_CUR)
            pkt_length = struct.unpack('I', open_file.read(4))[0]
            open_file.seek(4, io.SEEK_CUR)
            # Packet body
            pkt_body = open_file.read(pkt_length)
            if self.is_ipv4_tcp(pkt_body):
                data = self.get_tcp_data(pkt_body)
                tcp_stream.append(data)
            pcap_header += 16 + pkt_length
        open_file.close()
        print("dump tcp content finish,size:%d" % (len(tcp_stream)))
        logger.info("dump tcp content finish,size:%d len:%d buf:%s" % (len(tcp_stream), len(self.data_content), self.data_content[0:2000]))
        return tcp_stream

    def dump_reassemble_stream(self, client_ads, server_ads):
        """传入tcp Stream，对其进行过滤，返回无重传，无重流的tcpstream

        :param client_ads:获取client端的ip，port List
        :param server_ads:获取server端的ip，port List
        :return: 返回无重传，无重流的tcpstream List
        """
        tcp_stream = self.dump_tcp_content()
        reassemble_stream = TcpData(tcp_stream, client_ads, server_ads).reassemble_tcp()
        return reassemble_stream

    def dump_reassemble_streamV2(self, client_ads, server_ads):
        """传入tcp Stream，
        :return: 返回无过滤的流数据, 不包含rtsp信令
        """        
        tcp_stream = self.dump_tcp_content()
        #reassemble_stream = TcpData(tcp_stream, client_ads, server_ads).reassemble_tcp()
        file_handle = open(self.out_file, 'w', encoding='utf-8')
        pure_rtp_data = ''
        for meta in tcp_stream:
            if meta[7]:
                #print(meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6])
                rfc3984_start = struct.unpack('!B', meta[7][0: 1])[0]
                if 0x24 != rfc3984_start:
                    continue
                content = '{}'.format(meta[7])
                pure_rtp_data += content
                file_handle.write(content)
        file_handle.close()
        print("string pure meta data size: %d" % (len(pure_rtp_data)))
        logger.info("string pure meta data size: %d" % (len(pure_rtp_data)))
        pure_rtp_data = bytes(pure_rtp_data,encoding='utf-8')
        print("bytes pure meta data size: %d" % (len(pure_rtp_data)))
        logger.info("bytes pure meta data size: %d" % (len(pure_rtp_data)))
        data_index = 0
        while data_index < len(pure_rtp_data):
            start_flag = struct.unpack('!B', pure_rtp_data[data_index:data_index+1])[0] 
            interleaved_type = struct.unpack('!B', pure_rtp_data[data_index+1:data_index+2])[0]
            rtp_data_len = struct.unpack('!H', pure_rtp_data[data_index+2:data_index+4])[0] 
            print("flag:%x inter:%d len:%d index:%d" % (start_flag,interleaved_type,rtp_data_len, data_index))
            logger.info("flag:%x inter:%d len:%d index:%d" % (start_flag,interleaved_type,rtp_data_len, data_index))
            if 0x24 == start_flag:
                data_index += rtp_data_len + 4
            else:
                data_index += 1
        return tcp_stream

    def dump_reassemble_streamV3(self, client_ads, server_ads):
        """传入tcp Stream，
        :return: 返回无过滤的流数据, 不包含rtsp信令
        :notify: 码流先转成16进制字符串再处理, 发现有问题
        """        
        tcp_stream = self.dump_tcp_content()
        index = 0
        data_len = len(self.data_content)
        while index < data_len:
            tmp_head_4bytes = self.data_content[index:index+24]
            start_flag = int(self.data_content[index:index+2], 16)
            inter_type = int(self.data_content[index+2:index+4], 16)
            rtp_len = int(self.data_content[index+4:index+8], 16)
            rtp_seq = int(self.data_content[index+12:index+16], 16)
            logger.info("V3 dump content finish,head:%s seq:%d len:%d rtp:%d %x index:%d flag:%x type:%x" % (tmp_head_4bytes, rtp_seq, data_len, rtp_len, rtp_len, index, start_flag, inter_type))
            logger.info("%s" % (self.data_content[index:index + rtp_len*2 + 8]))
            if 0x24 == start_flag:
                index += (rtp_len * 2 + 8)
            else:
                index += 2
            
        return tcp_stream

    def write_file(self):
        tcp_data = self.dump_tcp_content()
        file_handle = open(self.out_file, 'w', encoding='utf-8')
        for meta in tcp_data:
            if meta[7]:
                # print(meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6])
                content = 'TCP的应用层数据:{}\n'.format(meta[7])
                file_handle.write(content)
        file_handle.close()



t1 = AnalysisPcap("rtsp.pcap", "out.txt")
a = t1.dump_reassemble_streamV3(['172.168.1.18', 58536], ['172.168.1.17', 554])
print("video:%d audio:%d drop:%d flow:%d" % (t1.video_frames, t1.audio_frames, t1.drop_vframes, t1.stream_flow))
logger.info("video:%d audio:%d drop:%d flow:%d" % (t1.video_frames, t1.audio_frames, t1.drop_vframes, t1.stream_flow))
print(a[3])
#t1.write_file()
