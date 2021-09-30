from config import Side
from proto.side_pb2_grpc import SideStub
from proto import message_pb2
from typing import Final
from collections import Mapping
import os
import yaml
import concurrent.futures
import time
import threading
import logging

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

GlobalBarrier = threading.Barrier(2, timeout=10)


class SideInfo:
    def __init__(
        self,
        dev_name,
        lid,
        gid,
        cq_id,
        pd_id,
        addr,
        len,
        rkey,
        lkey,
        qp_id,
        qp_num,
        mr_id,
    ):
        self.dev_name = dev_name
        self.lid = lid
        self.gid = gid
        self.cq_id = cq_id
        self.pd_id = pd_id
        self.addr = addr
        self.len = len
        self.rkey = rkey
        self.lkey = lkey
        self.qp_id = qp_id
        self.qp_num = qp_num
        self.mr_id = mr_id


class TestCase:
    TEST_DEF_DIR_ENV: Final = "TEST_DEF_DIR"
    DEFAULT_TEST_DEF_DIR: Final = "./case"

    def __init__(self, stub1: SideStub, stub2: SideStub, side1: Side, side2: Side):
        self.stub1 = stub1
        self.stub2 = stub2
        self.side1 = side1
        self.side2 = side2

    def run(self, test_name):
        test_def_dir = os.getenv(TestCase.TEST_DEF_DIR_ENV)
        if not test_def_dir:
            test_def_dir = TestCase.DEFAULT_TEST_DEF_DIR
        test_file_name = "{}/{}.yaml".format(test_def_dir, test_name)
        test = None
        try:
            test = yaml.load(open(test_file_name, "r"), Loader=Loader)
        except Exception as e:
            logging.error(f"Error to parse test file {test_file_name}")
            raise e

        side1_cmd = test.get("side_1")
        side2_cmd = test.get("side_2")

        try:
            info1, side1_cmd = prepare(side1_cmd, self.side1, self.stub1)
            info2, side2_cmd = prepare(side2_cmd, self.side2, self.stub2)
        except Exception as e:
            logging.error(
                f"Error when run prepare command for file {test_file_name}, {e}"
            )
            raise e

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            cmd_future = []
            future2side = {}
            if side1_cmd:
                tmp_future = executor.submit(
                    process_command,
                    side1_cmd,
                    self.side1,
                    info1,
                    self.stub1,
                    self.side2,
                    info2,
                    self.stub2,
                )
                future2side[tmp_future] = "side_1"
                cmd_future.append(tmp_future)
            if side2_cmd:
                tmp_future = executor.submit(
                    process_command,
                    side2_cmd,
                    self.side2,
                    info2,
                    self.stub2,
                    self.side1,
                    info1,
                    self.stub1,
                )
                future2side[tmp_future] = "side_2"
                cmd_future.append(tmp_future)

            for f in concurrent.futures.as_completed(cmd_future):
                try:
                    if not f.result():
                        logging.error(f"{future2side[f]} command failed")
                except Exception as e:
                    logging.error(
                        f"get an exception from {future2side[f]} command: {format(e)}"
                    )


def connect_qp(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    timeout = c_arg.get("timeout", 14)
    retry = c_arg.get("retry", 7)
    rnr_retry = c_arg.get("rnr_retry", 7)
    qp_flag = c_arg.get("qp_flag", 15)
    mtu = c_arg.get("mtu", 1024)
    sq_start_psn = c_arg.get("sq_start_psn", 0)
    rq_start_psn = c_arg.get("rq_start_psn", 0)
    max_rd_atomic = c_arg.get("max_rd_atomic", 1)
    max_dest_rd_atomic = c_arg.get("max_dest_rd_atomic", 1)
    min_rnr_timer = c_arg.get("min_rnr_timer", 0x12)

    self_stub.ConnectQp(
        message_pb2.ConnectQpRequest(
            dev_name=self_info.dev_name,
            qp_id=self_info.qp_id,
            access_flag=qp_flag,
            gid_idx=self_side.gid_idx(),
            ib_port_num=self_side.ib_port(),
            remote_qp_num=other_info.qp_num,
            remote_lid=other_info.lid,
            remote_gid=other_info.gid,
            timeout=timeout,
            retry=retry,
            rnr_retry=rnr_retry,
            mtu=mtu,
            sq_start_psn=sq_start_psn,
            rq_start_psn=rq_start_psn,
            max_rd_atomic=max_rd_atomic,
            max_dest_rd_atomic=max_dest_rd_atomic,
            min_rnr_timer=min_rnr_timer,
        )
    )
    return True


def sleep(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    len = c_arg.get("len")
    time.sleep(len)
    return True


def recv_pkt(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    retry = c_arg.get("wait_for_retry", 0)
    self_stub.RecvPkt(
        message_pb2.RecvPktRequest(
            wait_for_retry=retry, has_cqe=True, qp_id=self_info.qp_id
        )
    )
    return True


def local_check(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = []
    expected = []
    for r in c_arg.get("seg"):
        offset.append(r.get("offset", 0))
        e = r.get("expected")
        if not e:
            logging.error("should set expected in local_check")
            return False
        expected.append(bytes.fromhex(e))

    resp = self_stub.LocalCheckMem(
        message_pb2.LocalCheckMemRequest(
            mr_id=self_info.mr_id, offset=offset, expected=expected
        )
    )
    if resp.same:
        logging.info("value read correct")
    else:
        logging.info("value read INCORRECT")
    return resp.same


def local_write(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    content = c_arg.get("content")
    if not content:
        logging.error("should set content in local_write")
        return False
    content = bytes.fromhex(content)
    self_stub.LocalWrite(
        message_pb2.LocalWriteRequest(
            mr_id=self_info.mr_id, offset=offset, len=len(content), content=content
        )
    )
    return True


def remote_read(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    local_offset = c_arg.get("local_offset", 0)
    remote_offset = c_arg.get("remote_offset", 0)
    len = c_arg.get("len", 0)

    self_stub.RemoteRead(
        message_pb2.RemoteReadRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def remote_write(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    local_offset = c_arg.get("local_offset", 0)
    remote_offset = c_arg.get("remote_offset", 0)
    len = c_arg.get("len", 0)

    self_stub.RemoteWrite(
        message_pb2.RemoteWriteRequest(
            addr=(self_info.addr + local_offset),
            len=len,
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def remote_send(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    len = c_arg.get("len", 0)

    self_stub.RemoteSend(
        message_pb2.RemoteSendRequest(
            addr=(self_info.addr + offset),
            len=len,
            lkey=self_info.lkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def remote_atomic_cas(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    remote_offset = c_arg.get("remote_offset", 0)
    old_value = c_arg.get("old_value")
    new_value = c_arg.get("new_value")

    if not old_value:
        logging.error("old_value should be set")
        return False

    if not new_value:
        logging.error("new_value should be set")
        return False

    self_stub.RemoteAtomicCas(
        message_pb2.RemoteAtomicCasRequest(
            addr=(self_info.addr + offset),
            lkey=self_info.lkey,
            remote_addr=(other_info.addr + remote_offset),
            remote_key=other_info.rkey,
            old_value=old_value,
            new_value=new_value,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )

    return True


def local_recv(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    offset = c_arg.get("offset", 0)
    len = c_arg.get("len", 0)

    self_stub.LocalRecv(
        message_pb2.LocalRecvRequest(
            addr=(self_info.addr + offset),
            len=len,
            lkey=self_info.lkey,
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


def unblock_other(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    other_stub.UnblockRetry(message_pb2.UnblockRetryRequest())
    return True


def barrier(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    GlobalBarrier.wait()
    return True


def poll_complete(
    c_arg,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    self_stub.PollComplete(
        message_pb2.PollCompleteRequest(
            qp_id=self_info.qp_id,
            cq_id=self_info.cq_id,
        )
    )
    return True


COMMAND_MAP: Final = {
    "connect_qp": connect_qp,
    "sleep": sleep,
    "recv_pkt": recv_pkt,
    "local_check": local_check,
    "local_write": local_write,
    "remote_read": remote_read,
    "remote_write": remote_write,
    "remote_send": remote_send,
    "remote_atomic_cas": remote_atomic_cas,
    "local_recv": local_recv,
    "unblock_other": unblock_other,
    "barrier": barrier,
    "poll_complete": poll_complete,
}


def process_command(
    cmds,
    self_side: Side,
    self_info: SideInfo,
    self_stub: SideStub,
    other_side: Side,
    other_info: SideInfo,
    other_stub: SideStub,
):
    for c in cmds:
        if not c["name"]:
            logging.error("command missing name")
            return False
        fun = COMMAND_MAP[c["name"]]
        if fun:
            try:
                if not fun(
                    c,
                    self_side,
                    self_info,
                    self_stub,
                    other_side,
                    other_info,
                    other_stub,
                ):
                    logging.error(f'failed to executed command {c["name"]}')
                    return False
            except Exception as e:
                logging.error(f'failed to executed command {c["name"]}, {e}')
                return False
        else:
            logging.error(f'command {c["name"]} is not in the definition')
            return False
    return True


def prepare(cmds, side: Side, stub: SideStub):
    first_cmd = cmds[0]
    if first_cmd["name"] != "prepare":
        raise RuntimeError(
            f"first command should be prepare, but it's {first_cmd['name']}"
        )

    mr_len = first_cmd.get("mr_len", 1024)
    mr_flag = first_cmd.get("mr_flag", 15)

    dev_name = side.dev_name()
    dev_name = dev_name if dev_name else ""
    response = stub.OpenDevice(message_pb2.OpenDeviceRequest(dev_name=dev_name))
    dev_name = response.dev_name
    logging.info(f"device name is {dev_name}")

    response = stub.QueryPort(
        message_pb2.QueryPortRequest(dev_name=dev_name, ib_port_num=side.ib_port())
    )
    lid = response.lid

    response = stub.QueryGid(
        message_pb2.QueryGidRequest(
            dev_name=dev_name, ib_port_num=side.ib_port(), gid_idx=side.gid_idx()
        )
    )

    gid = response.gid_raw

    response = stub.CreateCq(message_pb2.CreateCqRequest(dev_name=dev_name, cq_size=10))
    cq_id = response.cq_id

    response = stub.CreatePd(message_pb2.CreatePdRequest(dev_name=dev_name))
    pd_id = response.pd_id

    response = stub.CreateMr(
        message_pb2.CreateMrRequest(pd_id=pd_id, len=mr_len, flag=mr_flag)
    )
    addr = response.addr
    len = response.len
    rkey = response.rkey
    lkey = response.lkey
    mr_id = response.mr_id

    response: message_pb2.CreateQpResponse = stub.CreateQp(
        message_pb2.CreateQpRequest(pd_id=pd_id, qp_type=0, cq_id=cq_id)
    )
    qp_id = response.qp_id
    qp_num = response.qp_num

    return (
        SideInfo(
            dev_name,
            lid,
            gid,
            cq_id,
            pd_id,
            addr,
            len,
            rkey,
            lkey,
            qp_id,
            qp_num,
            mr_id,
        ),
        cmds[1:],
    )
