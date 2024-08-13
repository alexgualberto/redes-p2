import asyncio
from tcputils import *
import os
import time
import random

MSS = 1460  # Definindo o tamanho máximo do segmento

def estimatedRTT(prev_val, alpha, SRTT):
    return (1 - alpha) * prev_val + alpha * SRTT

def devRTT(prev_val, beta, SRTT, ERTT):
    return (1 - beta) * prev_val + beta * abs(SRTT - ERTT)

def TimeoutInterval(ERTT, DRTT):
    return ERTT + 4 * DRTT

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def kill_conexao(self, conexao):
        src_addr, src_port, dst_addr, dst_port = conexao.id_conexao
        new_segment = make_header(dst_port, src_port, 1, conexao.seq_no + 1, FLAGS_ACK)
        FIN_dados = [new_segment, dst_addr]
        self.rede.enviar(FIN_dados[0], FIN_dados[1])
        self.conexoes.pop(conexao.id_conexao)

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            new_seq_no = random.randint(1, 1000)
            conexao.seq_no = conexao.next_seq_no = new_seq_no
            conexao.ack_no = seq_no + 1

            new_segment = fix_checksum(make_header(dst_port, src_port, conexao.seq_no, conexao.ack_no, FLAGS_SYN + FLAGS_ACK), dst_addr, src_addr)
            dados = [new_segment, src_addr]
            self.rede.enviar(dados[0], dados[1])
            if self.callback:
                self.callback(conexao)
        elif (flags & FLAGS_FIN) == FLAGS_FIN:
            curr_conexao = self.conexoes[id_conexao]

            new_segment = make_header(dst_port, src_port, seq_no, seq_no + 1, FLAGS_ACK)
            ACK_dados = [new_segment, src_addr]
            self.rede.enviar(ACK_dados[0], ACK_dados[1])

            curr_conexao.callback(curr_conexao, b'')
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' % (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no = None
        self.ack_no = None
        self.next_seq_no = None
        self.segments = []
        self.timer = None
        self.timer_running = False
        self.time_SRTT = None
        self.SRTT = None
        self.ERTT = None
        self.DRTT = None
        self.cwnd = 1 * MSS
        self.ssthresh = 64 * MSS
        self.dup_ack_count = 0

    def start_timer(self, data, dst_addr):
        timeout = 1
        if self.ERTT is not None:
            timeout = TimeoutInterval(self.ERTT, self.DRTT)
            self.ERTT = estimatedRTT(self.ERTT, 0.125, self.SRTT)
            self.DRTT = devRTT(self.DRTT, 0.25, self.SRTT, self.ERTT)
        self.timer = asyncio.get_event_loop().call_later(timeout, self.timeout, data, dst_addr)

    def timeout(self, segment, dst_addr):
        self.timer_running = False
        self.ssthresh = max(self.cwnd // 2, 1 * MSS)
        self.cwnd = 1 * MSS
        self.retransmit(segment, dst_addr)

    def retransmit(self, segment, dst_addr):
        print("Retransmitindo segmento...")
        self.servidor.rede.enviar(segment, dst_addr)
        self.start_timer(segment, dst_addr)

    def confirmar_pacote(self, ack_no):
        self.timer_running = False
        if self.timer:
            self.timer.cancel()
        if self.cwnd < self.ssthresh:
            self.cwnd += MSS
        else:
            self.cwnd += MSS * (MSS / self.cwnd)

        if len(self.segments) != 0:
            segment = self.segments.pop(0)
            self.seq_no = ack_no
            if len(self.segments) != 0:
                next_seg = self.segments[0]
                src_addr, src_port, dst_addr, dst_port = self.id_conexao
                payload = next_seg[4 * (FLAGS_ACK >> 12):]
                gambiarra = fix_checksum(make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK) + payload, src_addr, dst_addr)
                self.servidor.rede.enviar(gambiarra, dst_addr)
                self.timer_running = True
                self.time_SRTT = time.time()
                self.start_timer(gambiarra, dst_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if seq_no == self.ack_no:
            self.ack_no = seq_no + len(payload)

            if len(payload) > 0:
                new_segment = fix_checksum(make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
                self.servidor.rede.enviar(new_segment, dst_addr)
                self.callback(self, payload)
            else:
                self.confirmar_pacote(ack_no)
                if self.time_SRTT is not None:
                    self.SRTT = time.time() - self.time_SRTT
                    if self.ERTT is None:
                        self.ERTT = self.SRTT
                        self.DRTT = self.SRTT / 2

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        if len(dados) > MSS:
            seqno_add = 0
        else:
            seqno_add = 1

        send_data = []
        while len(dados) > 0:
            d = dados[:MSS]
            send_data.append(d)
            dados = dados[MSS:]

        for data in send_data:
            print("curr seq_no = ", self.next_seq_no + seqno_add)
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            new_segment = fix_checksum(make_header(src_port, dst_port, self.next_seq_no + seqno_add, self.ack_no, FLAGS_ACK) + data, src_addr, dst_addr)
            seqno_add += len(data)
            self.segments.append(new_segment)
            if not self.timer_running:
                self.time_SRTT = time.time()
                self.servidor.rede.enviar(new_segment, dst_addr)
                self.start_timer(new_segment, dst_addr)
                self.timer_running = True
        self.next_seq_no += seqno_add

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        new_segment = make_header(src_port, dst_port, self.seq_no + 1, 1, FLAGS_FIN)
        FIN_dados = [new_segment, src_addr]
        self.servidor.rede.enviar(FIN_dados[0], FIN_dados[1])
        self.servidor.kill_conexao(self)
