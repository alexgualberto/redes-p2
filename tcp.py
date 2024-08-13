import asyncio
from tcputils import *
import os
import time
import random

def estimatedRTT(prev_val, alpha, SRTT):
    return (1 - alpha)*prev_val+alpha*SRTT


def devRTT(prev_val, beta, SRTT, ERTT):
    return (1 - beta)*prev_val+beta*abs(SRTT-ERTT)


def TimeoutInterval(ERTT, DRTT):
    return ERTT + 4*DRTT


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def kill_conexao(self, conexao):
        src_addr, src_port, dst_addr, dst_port = conexao.id_conexao
        new_segment = make_header(
            dst_port, src_port, 1, conexao.seq_no + 1, FLAGS_ACK)
        FIN_dados = [new_segment, dst_addr]
        self.rede.enviar(FIN_dados[0], FIN_dados[1])
        self.conexoes.pop(conexao.id_conexao)
        pass

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            # Não Tenho certeza disso aqui em baixo
            new_seq_no = random.randint(1, 1000)
            conexao.seq_no = conexao.next_seq_no = new_seq_no
            conexao.ack_no = seq_no + 1
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            new_segment = fix_checksum(make_header(
                dst_port, src_port, conexao.seq_no, conexao.ack_no, FLAGS_SYN+FLAGS_ACK), dst_addr, src_addr)
            dados = [new_segment, src_addr]
            self.rede.enviar(dados[0], dados[1])
            if self.callback:
                self.callback(conexao)
        elif (flags & FLAGS_FIN) == FLAGS_FIN:
            curr_conexao = self.conexoes[id_conexao]
            # ENVIAR ACK
            new_segment = make_header(
                dst_port, src_port, seq_no, seq_no + 1, FLAGS_ACK)
            ACK_dados = [new_segment, src_addr]
            self.rede.enviar(ACK_dados[0], ACK_dados[1])
            # EXECUTAR CALLBACK DA CONEXAO COM DADOS = b''
            curr_conexao.callback(curr_conexao, b'')
            # O ENVIO DO 'FIN' É TRATADO EM conexao.fechar()
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


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
        # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida

        # self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    # criar funções de start timer, timeout, reenviar
    def start_timer(self, data, dst_addr):
        print("chamou start timer")
        timeout = 1
        if not self.ERTT is None:
            timeout = TimeoutInterval(self.ERTT, self.DRTT)
            self.ERTT = estimatedRTT(self.ERTT, .125, self.SRTT)
            self.DRTT = devRTT(self.DRTT, .25, self.SRTT, self.ERTT)
        self.timer = asyncio.get_event_loop().call_later(timeout, self.timeout, data, dst_addr)

        # Esta função é só um exemplo e pode ser removida
    def timeout(self, segment, dst_addr):
        self.timer_running = False
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(
            segment)
        payload = segment[4*(flags >> 12):]
        gambiarra = fix_checksum(make_header(
            src_port, dst_port, seq_no - 1, ack_no, flags) + payload, src_addr, dst_addr)
        print("deu timeout = ", seq_no - 1)
        self.servidor.rede.enviar(gambiarra, dst_addr)

    def confirmar_pacote(self):
        print("confirmou pacote")
        self.timer_running = False
        if self.timer:
            self.timer.cancel()
        if len(self.segments) != 0:
            segment = self.segments.pop(0)
            src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(
                segment)
            self.seq_no = seq_no
            if len(self.segments) != 0:
                print("len da fila de espera pra enviar = ", len(self.segments))
                next_seg = self.segments[0]
                src_addr, src_port, dst_addr, dst_port = self.id_conexao
                src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(
                    next_seg)
                payload = next_seg[4*(flags >> 12):]
                gambiarra = fix_checksum(make_header(
                    src_port, dst_port, seq_no - 1, ack_no, flags) + payload, src_addr, dst_addr)
                self.servidor.rede.enviar(gambiarra, dst_addr)
                self.timer_running = True
                self.time_SRTT = time.time()
                self.start_timer(gambiarra, dst_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):

        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if(seq_no == self.ack_no):
            self.ack_no = seq_no + len(payload)
            # Chame self.callback(self, dados) para passar dados para a camada de aplicação após

            if len(payload) > 0:
                new_segment = fix_checksum(make_header(
                    src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
                self.servidor.rede.enviar(new_segment, dst_addr)
            # timer
                self.callback(self, payload)
            else:
                # tratar confirmação de recebimento de segmento
                self.confirmar_pacote()
                if not self.time_SRTT is None:
                    self.SRTT = time.time() - self.time_SRTT
                    if self.ERTT is None:
                        self.ERTT = self.SRTT
                        self.DRTT = self.SRTT / 2
                        print("ertt, drtt = ", self.ERTT, self.DRTT)
                pass

        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """

        if len(dados) > MSS:
            seqno_add = 0
        else:
            seqno_add = 1

        send_data = []
        while(len(dados) > 0):
            d = dados[:MSS]
            send_data.append(d)
            dados = dados[MSS:]

        print([len(d) for d in send_data])

        for data in send_data:
            # TODO: implemente aqui o envio de dados.
            # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
            # que você construir para a camada de rede.
            print("curr seq_no = ", self.next_seq_no + seqno_add)
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            new_segment = fix_checksum(make_header(
                src_port, dst_port, self.next_seq_no + seqno_add, self.ack_no, FLAGS_ACK) + data, src_addr, dst_addr)
            seqno_add += len(data)
            self.segments.append(new_segment)
            print("antes timer = ", self.next_seq_no)
            if self.timer_running == False:
                self.time_SRTT = time.time()
                print("fez envio")
                self.servidor.rede.enviar(new_segment, dst_addr)
                self.start_timer(new_segment, dst_addr)
                self.timer_running = True
        self.next_seq_no += seqno_add

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        new_segment = make_header(
            src_port, dst_port, self.seq_no + 1, 1, FLAGS_FIN)
        FIN_dados = [new_segment, src_addr]
        self.servidor.rede.enviar(FIN_dados[0], FIN_dados[1])
        self.servidor.kill_conexao(self)
