import asyncio
import math
import time
from tcputils import *

MSS = 1460  # Tamanho Máximo do Segmento

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
            print("descartando segmento com checksum incorreto")
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            ack_no = seq_no + 1
            syn_ack_segment = fix_checksum(
                make_header(dst_port, src_port, conexao.seq_no, ack_no, FLAGS_SYN | FLAGS_ACK),
                dst_addr,
                src_addr,
            )
            self.rede.enviar(syn_ack_segment, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print("%s:%d -> %s:%d (pacote associado a conexão desconhecida)" % (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no = seq_no + 1
        self.ack_no = seq_no + 1
        self.unacked_data = b""
        self.cwnd = 1 * MSS
        self.ssthresh = 64 * MSS
        self.timer = None
        self.retransmitting = False

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        # Verifica se o segmento está no número de sequência esperado
        if seq_no == self.ack_no:
            self.ack_no += len(payload)
            if payload:
                self.callback(self, payload)
                ack_segment = fix_checksum(
                    make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK),
                    dst_addr,
                    src_addr,
                )
                self.servidor.rede.enviar(ack_segment, src_addr)

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1
            fin_ack_segment = fix_checksum(
                make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK),
                dst_addr,
                src_addr,
            )
            self.servidor.rede.enviar(fin_ack_segment, src_addr)
            self.callback(self, b"")
            del self.servidor.conexoes[self.id_conexao]

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.seq_no:
            self.unacked_data = self.unacked_data[ack_no - self.seq_no:]
            self.seq_no = ack_no
            if self.unacked_data:
                self.start_timer()
            else:
                self.cancel_timer()

    def start_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(1, self.handle_timeout)

    def cancel_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def handle_timeout(self):
        self.retransmitting = True
        self.retransmit()
        self.start_timer()

    def retransmit(self):
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
        segment = fix_checksum(header + self.unacked_data[:MSS], dst_addr, src_addr)
        self.servidor.rede.enviar(segment, src_addr)

    def enviar(self, dados):
        self.unacked_data += dados
        self.send_pending_data()

    def send_pending_data(self):
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
        n_segments = math.ceil(len(self.unacked_data) / MSS)
        for i in range(n_segments):
            segment = self.unacked_data[i * MSS : (i + 1) * MSS]
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            full_segment = fix_checksum(header + segment, dst_addr, src_addr)
            self.servidor.rede.enviar(full_segment, src_addr)
            if not self.timer:
                self.start_timer()
            self.seq_no += len(segment)

    def fechar(self):
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
        fin_segment = fix_checksum(
            make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN),
            dst_addr,
            src_addr,
        )
        self.servidor.rede.enviar(fin_segment, src_addr)

