import asyncio
import math
import time
import secrets
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
        (
            src_port,
            dst_port,
            seq_no,
            ack_no,
            flags,
            window_size,
            checksum,
            urg_ptr,
        ) = read_header(segment)

        if dst_port != self.porta:
            return
        if (
            not self.rede.ignore_checksum
            and calc_checksum(segment, src_addr, dst_addr) != 0
        ):
            print("descartando segmento com checksum incorreto")
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # Inicializando conexão e enviando SYN + ACK
            seq_no_svr = secrets.randbelow(65535)
            ack_no_svr = seq_no + 1
            header = make_header(dst_port, src_port, seq_no_svr, ack_no_svr, FLAGS_SYN | FLAGS_ACK)
            segment_svr = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(segment_svr, src_addr)
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, ack_no_svr, seq_no_svr + 1)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print(
                "%s:%d -> %s:%d (pacote associado a conexão desconhecida)"
                % (src_addr, src_port, dst_addr, dst_port)
            )

class Conexao:
    def __init__(self, servidor, id_conexao, ack_no, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.temp_ini = None
        self.temp_fin = None
        self.timer = None
        self.devr = None  
        self.ack_no = ack_no
        self.seq_no = seq_no
        self.sendb = seq_no
        self.ult_seq = seq_no
        self.unacked = b""
        self.unsent = b""
        self.byt_ack = 0
        self.interv = 1
        self.iter_inic = True
        self.window = 1
        self.closing = False
        self.retransm = False
        
    def timer_limit(self):
        self.timer = None
        self.window = max(self.window // 2, 1)
        self.retrans()
        self.timer_inic()

    def timer_inic(self):
        if self.timer:
            self.timer_para()
        self.timer = asyncio.get_event_loop().call_later(self.interv, self.timer_limit)
        
    def timer_para(self):
        self.timer.cancel()
        self.timer = None

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if seq_no != self.ack_no:
            return

        self.ack_no += len(payload)
        
        if payload:
            self.callback(self, payload)

        # Enviar ACK para confirmar o recebimento
        header = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_no, self.ack_no, FLAGS_ACK)
        ack_segment = fix_checksum(header, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(ack_segment, self.id_conexao[2])

        # Tratamento de FIN flag para fechamento de conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.closing = True
            self.ack_no += 1
            self.enviar_seg_ack(b"")
            del self.servidor.conexoes[self.id_conexao]
            self.callback(self, b"")

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.sendb:
            self.unacked = self.unacked[ack_no - self.sendb :]
            self.byt_ack = ack_no - self.sendb
            self.sendb = ack_no
            if self.unacked:
                self.timer_inic()
            else:
                if self.timer:
                    self.timer_para()
                if not self.retransm:
                    self.temp_fin = time.time()
                    self.calcula_rtt()   
                else:
                    self.retransm = False

        if self.byt_ack >= MSS:
            self.byt_ack = self.byt_ack + MSS
            self.window = self.window + 1
            self.envio_pendente()

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        self.unsent = self.unsent + dados
        pront = self.unsent[: (self.window * MSS)]
        self.unsent = self.unsent[(self.window * MSS) :]
        self.ult_seq = self.seq_no + len(pront)
        n_segment = math.ceil(len(pront) / MSS)
        for i in range(n_segment):
            segment = pront[i * MSS : (i + 1) * MSS]
            self.enviar_seg_ack(segment)

    def fechar(self):
        ack_segment = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, FLAGS_FIN)
        self.servidor.rede.enviar(fix_checksum(ack_segment, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])
        
    def retrans(self):
        self.retransm = True
        tam = min(MSS, len(self.unacked))
        data = self.unacked[:tam]
        self.enviar_seg_ack(data)

    def enviar_seg_ack(self, data):
        seq_no = None
        if self.retransm:
            seq_no = self.sendb
        else:
            seq_no = self.seq_no
            self.seq_no = self.seq_no + len(data)
            self.unacked = self.unacked + data
            self.temp_ini = time.time()        
        pac = make_header(self.id_conexao[1], self.id_conexao[3], seq_no, self.ack_no, FLAGS_ACK)
        ack_segment = fix_checksum(pac + data, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(ack_segment, self.id_conexao[1])
        if not self.timer and not self.closing:
            self.timer_inic() 

    def envio_pendente(self):
        tam_pendente = (self.window * MSS) - len(self.unacked)
        if tam_pendente > 0:
            pront = self.unsent[:tam_pendente]
            self.unsent = self.unsent[tam_pendente:]
            self.ult_seq = self.seq_no + len(pront)
            n_segment = math.ceil(len(pront) / MSS)
            
            for i in range(n_segment):
                segment = pront[i * MSS : (i + 1) * MSS]
                self.enviar_seg_ack(segment)
                         
    def calcula_rtt(self):
        self.sample_rtt = self.temp_fin - self.temp_ini
        if self.iter_inic:
            self.iter_inic = False
            self.devr = self.sample_rtt / 2
            self.estimated_rtt = self.sample_rtt
        else:
            self.estimated_rtt = ((0.75) * self.estimated_rtt) + (0.25 * self.sample_rtt)
            self.devr = ((0.5) * self.devr) + (0.5 * abs(self.sample_rtt - self.estimated_rtt))
        self.interv = self.estimated_rtt + (4 * self.devr)
