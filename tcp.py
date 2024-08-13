import asyncio
import math
import random
import time
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no = random.randint(0, 0xffff)
        self.ack_no = seq_no + 1
        self.fin = False
        self.unacked = b''
        self.unsent = b''
        self.estimatedRTT = None
        self.timeoutInterval = 1
        self.cwnd = 1
        src_addr, src_port, dst_addr, dst_port = id_conexao
        self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_SYN + FLAGS_ACK), dst_addr, src_addr), src_addr)
        self.seq_no += 1
        self.base_seq = self.seq_no
        self.timer = None

    def retransmitir(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segmento = self.unacked[:MSS]
        self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.base_seq, self.ack_no, FLAGS_ACK) + segmento, dst_addr, src_addr), src_addr)
        self.t0 = None
        self.cwnd = math.ceil(self.cwnd/2)
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmitir)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.t1 = time.time()
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self, b'')
            self.ack_no = seq_no + 1
            self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr), src_addr)
        if (flags & FLAGS_ACK) == FLAGS_ACK:
            if self.fin and ack_no == self.seq_no + 1:
                del self.servidor.conexoes[self.id_conexao]
            elif ack_no > self.base_seq:
                self.timer.cancel()
                if self.t0 != None:
                    self.cwnd += 1
                    self.sampleRTT = self.t1 - self.t0
                    if self.estimatedRTT == None:
                        self.estimatedRTT = self.sampleRTT
                        self.devRTT = self.sampleRTT / 2
                    else:
                        self.estimatedRTT = (1 - 0.125) * self.estimatedRTT + 0.125 * self.sampleRTT
                        self.devRTT = (1 - 0.25) * self.devRTT + 0.25 * abs(self.sampleRTT - self.estimatedRTT)
                    self.timeoutInterval = self.estimatedRTT + 4 * self.devRTT
                self.unacked = self.unacked[ack_no - self.base_seq:]
                self.base_seq = ack_no
                if len(self.unacked) > 0:
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmitir)
                else:
                    self.timer = None
                if len(self.unsent) > 0:
                    self.enviar(b'')
        if seq_no == self.ack_no and len(payload) > 0:
            self.callback(self, payload)
            self.ack_no += len(payload)
            self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr), src_addr)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.unsent += dados
        for _ in range(0, self.cwnd):
            if len(self.unsent) > 0:
                segmento = self.unsent[:MSS]
                self.unsent = self.unsent[MSS:]
                self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK) + segmento, dst_addr, src_addr), src_addr)
                self.unacked += segmento
                self.seq_no += len(segmento)
        self.t0 = time.time()
        if self.timer == None:
            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmitir)

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN), dst_addr, src_addr), src_addr)
        self.fin = True
