"""Bounded optical reads and standard DVD authentication. No disc/flash writes or hub reset."""
import json, sys, time
from datetime import datetime
from pathlib import Path
from dvd_auth_commands import (validate_auth_cdb, REPORT_FORMATS,
                               STRUCTURE_FORMATS, SEND_FORMATS)

AUTH_DATA_IN_KINDS = frozenset(
    [kind for kind, _ in REPORT_FORMATS.values()] +
    [kind for kind, _ in STRUCTURE_FORMATS.values()] + ['capability_probe'])
AUTH_DATA_OUT_KINDS = frozenset(kind for kind, _ in SEND_FORMATS.values())
sys.path.insert(0,str(Path('outputs/initio-sata').resolve()))
import InitioSata as api
LOG=Path('outputs/initio/live-usb-reader.jsonl')
def log(stage, **kw):
    with LOG.open('a') as f:f.write(json.dumps({'time':datetime.now().astimezone().isoformat(),'stage':stage,**kw})+'\n')
def mem(h,a,n):
    start=a&~1;end=(a+n+1)&~1;data=bytearray()
    h.command(0x8201,a>>16)
    for pos in range(start,end,2):
        h.command(0x8101,pos&65535);data.extend(h.command(0xba03,length=2))
    return bytes(data[a-start:a-start+n])
def read(h,a):
    h.command(0x8201,1);h.command(0x8101,a)
    return h.command(0xba03,length=2)[0]
WRITES={0xe013,0xe010,0xe00c,0xe034,0xe008,0xe030,0xe031,0xe000,0xe001,0xe002,
        0xe007,0xe028,0xe020,0xe166,0xe168,*range(0xe03c,0xe040),
        0xe01f,0xe180,0xe184,0xe185,0xe024,0xe08c,0xc980,0xc988,0xe165,0xc98b,
        *range(0xe188,0xe18c),*range(0xe190,0xe1a0),*range(0xc984,0xc98c)}
def write(h,a,v):
    if a not in WRITES:raise RuntimeError('Address outside mirrored ROM sequence')
    h.command(0x8101,a);h.command(0x8201,1);h.command(0xda02,v,2,write=True)
def count(h):return int.from_bytes(mem(h,0x1c914,2),'little')
def state(h):return {'phy':read(h,0xe014),'task':read(h,0xe08c),'error':read(h,0xe08d),'event':read(h,0xe000),'fifo_count':count(h)}

# Additional writes are limited to the ROM's ATAPI context translation path.
FIELDS=(0xcc01,0xcc03,0xcc0e,0xcc2a,*range(0xcc08,0xcc0c),*range(0xcc10,0xcc1c))
MODE=(0xe069,0xe06a,0xe06c,0xd146,0xd147)
WRITES.update((*FIELDS,*MODE,0xd1d0,0xc04c))
def restore_fields(h,saved):
    for a,v in saved.items():write(h,a,v)
    mismatches={}
    for a,v in saved.items():
        actual=read(h,a)
        if actual!=v:mismatches[hex(a)]={'expected':v,'actual':actual}
    return mismatches


def packet(h,context,cdb,size,label):
    global issued
    if len(cdb)!=12 or cdb[0] not in (0x12,0x03,0x25,0x28) or not 0<size<=4096:
        raise RuntimeError('Command outside read-only probe scope')
    if cdb[0]==0x28 and (int.from_bytes(cdb[2:6],'big')!=16 or int.from_bytes(cdb[7:9],'big')!=1):
        raise RuntimeError('Sector probe is restricted to one block at LBA16')
    result={'ok':False,'label':label}
    try:
        if read(h,0xc04c)!=context:raise RuntimeError('USB context changed')
        desired={0xcc01:original[0xcc01]|0x80,0xcc03:0xd0,0xcc0e:0x40,0xcc2a:0}
        desired.update({0xcc08+i:v for i,v in enumerate(size.to_bytes(4,'little'))})
        desired.update({0xcc10+i:v for i,v in enumerate(cdb)})
        for a,v in desired.items():write(h,a,v)
        if read(h,0xc04c)!=context or any(read(h,a)!=v for a,v in desired.items()):
            raise RuntimeError('Context injection did not verify')
        write(h,0xc980,1)
        for i,v in enumerate(bytes.fromhex('0000000000000801')):write(h,0xc984+i,v)
        for a in (0xe008,0xe030,0xe031,0xe000,0xe001):write(h,a,0xff)
        write(h,0xe01f,1);write(h,0xd1d0,context)
        deadline=time.monotonic()+1
        while read(h,0xd1d1)&0x80:
            if time.monotonic()>deadline:raise RuntimeError('Translator timeout')
            time.sleep(.005)
        for i,v in enumerate(size.to_bytes(4,'little')):write(h,0xe188+i,v)
        log('packet_request',label=label,cdb=cdb.hex(),length=size,context=context)
        issued=True
        write(h,0xe024,1);write(h,0xe08c,0x80);write(h,0xc980,1);write(h,0xc988,0x25)
        complete=False;last=None;deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            s=state(h)
            if s!=last:log('packet_sample',label=label,state=s)
            last=s
            if s['event']&0x10:raise RuntimeError('SATA error event')
            if not s['phy']&1:raise RuntimeError('SATA link lost')
            if s['event']&0x80:complete=True;break
            time.sleep(.02)
        if not complete:raise RuntimeError('Packet completion timeout')
        write(h,0xe000,0xc8);write(h,0xc980,1);write(h,0xc988,read(h,0xc988)&0xf0);write(h,0xe165,0x20)
        s=state(h);result.update(s);log('packet_completed',label=label,state=s)
        if s['task']&0x80:raise RuntimeError('Packet remained BUSY after completion')
        if s['task']&1:return result
        available=count(h);deadline=time.monotonic()+1
        while available<size and time.monotonic()<deadline:
            time.sleep(.02);available=count(h)
        if available!=size:raise RuntimeError('Unexpected FIFO length '+str(available))
        h.command(0x8201,1);data=bytearray();deadline=time.monotonic()+10
        for _ in range(size):
            if time.monotonic()>deadline:raise RuntimeError('FIFO read deadline exceeded')
            h.command(0x8101,0xc884);data.extend(h.command(0xba03,length=1))
        remaining=count(h)
        log('packet_data',label=label,length=len(data),remaining=remaining,prefix=data[:96].hex(),sha256=__import__('hashlib').sha256(data).hexdigest())
        if remaining:raise RuntimeError('FIFO did not drain')
        result.update(ok=True,data=bytes(data))
        return result
    finally:
        if issued:
            write(h,0xe165,0x20);write(h,0xc980,1);write(h,0xc98b,1);read(h,0xc98b);write(h,0xc988,0)
            issued=False

def sense(h,context):
    r=packet(h,context,bytes.fromhex('030000001000000000000000'),16,'request_sense')
    if r['ok']:
        d=r['data'];fmt=d[0]&0x7f
        r.update(sense_format=fmt,sense_key=(d[1] if fmt in (0x72,0x73) else d[2])&15,
                 asc=d[2] if fmt in (0x72,0x73) else d[12],ascq=d[3] if fmt in (0x72,0x73) else d[13])
        log('sense_decoded',**{k:v for k,v in r.items() if k!='data'})
    return r


from scsi_block_worker import ScsiRead
MODE=(*MODE,0xd045)
WRITES.update((0xd045,0xd100,0xd114,0xd117,0xd138,*range(0xd11c,0xd120)))



WRITES.update((0xcc0f,0xcc2f,0xcc32,0xcc33,0xd115))
WRITES.update((0xd130,0xd119))  # ROM71FD / 2074: bounded authentication OUT.
OWN_CDB = bytes.fromhex('280000000010000001000000')
ZERO_CDB = bytes.fromhex('280000000000000001000000')

def check_bound(deadline, watch_worker=False):
    if time.monotonic() >= deadline:
        raise RuntimeError('Overall queue-probe deadline exceeded')
    if watch_worker and disk.result is not None:
        raise RuntimeError('Windows worker already completed; no further command/status sent')

def usb_gate(h,deadline=None,watch_worker=False):
    end=time.monotonic()+0.5
    if deadline is not None:end=min(end,deadline)
    while True:
        check_bound(end,watch_worker)
        value=read(h,0xd100)
        if value & 0x10:
            raise RuntimeError('USB reset state; normal path not assumed')
        if not(read(h,0xd114)&1):return value
        time.sleep(.005)

def settle_csw(h,deadline,watch_worker):
    time.sleep(.005)
    usb_gate(h,deadline,watch_worker)

def classify_cdb(cdb,size,direction,allow_own):
    if len(cdb)!=12:
        raise RuntimeError('Unexpected CDB window length')
    op=cdb[0]
    if op==0 and size==0 and cdb==bytes(12):
        return 'tur'
    if op==0x1e and size==0 and cdb[1:4]==bytes(3) and cdb[4] in (0,1) and cdb[5:]==bytes(7):
        return 'prevent_allow'
    if op in (0xa3,0xa4,0xad,0x46):
        auth_direction = 'in' if direction & 0x80 else ('out' if size else 'none')
        try:
            return validate_auth_cdb(cdb, size, auth_direction)
        except ValueError as exc:
            raise RuntimeError('Queued authentication command rejected: ' + str(exc)) from exc
    if not(direction&0x80):
        raise RuntimeError('Data-out or unverified command direction is outside scope')
    if op==3 and 0<size<=64 and cdb[1] in (0,1) and cdb[2:4]==bytes(2) and cdb[4]==size and cdb[5:]==bytes(7):
        return 'request_sense'
    if op==0x12 and 0<size<=96 and cdb[1] in (0,1) and (cdb[1]&1 or cdb[2]==0) and int.from_bytes(cdb[3:5],'big')==size and cdb[5:]==bytes(7):
        return 'inquiry'
    if op==0x25 and size==8 and cdb==bytes.fromhex('250000000000000000000000'):
        return 'read_capacity'
    if op==0x1a and 0<size<=255 and cdb[1]&~8==0 and cdb[3] in (0,255) and cdb[4]==size and cdb[5:]==bytes(7):
        return 'mode_sense6'
    if op==0x28 and cdb[1]==0 and cdb[6]==0 and cdb[9:]==bytes(3):
        lba=int.from_bytes(cdb[2:6],'big'); blocks=int.from_bytes(cdb[7:9],'big')
        if 1<=blocks<=MAX_BLOCKS and size==blocks*2048 and lba+blocks<=CAPACITY_BLOCKS:
            return 'read_blocks'
    raise RuntimeError('Queued CDB/length is outside the fixed read-only allowlist')

def claim_pending(h,allow_own,deadline,watch_worker=False):
    if watch_worker and disk.result is not None:return None
    started=time.monotonic();phases={};ctx=None
    def timed(name,operation):
        before=time.monotonic()
        try:return operation()
        finally:phases[name]=time.monotonic()-before
    try:
        pending=timed('pending_poll',lambda:read(h,0xc051))
        check_bound(deadline)
        if not(pending&0x10):return None
        # Waiting reads must not claim a new CBW if the worker finishes meanwhile.
        timed('usb_gate',lambda:usb_gate(h,deadline,False))
        check_bound(deadline)
        if watch_worker and disk.result is not None:return None
        # D03A is read exactly once, and only with the pending-command flag.
        def pop_context():
            h.command(0x8201,1);h.command(0x8101,0xd03a)
            return h.command(0xba03,length=1)[0]
        ctx=timed('claim_context',pop_context)
        check_bound(deadline)
        def select_context():
            write(h,0xc04c,ctx)
            return read(h,0xc04c)
        if timed('select_context',select_context)!=ctx:
            raise RuntimeError('Queued context selection failed')
        check_bound(deadline)
        metadata=timed('metadata',lambda:mem(h,0x1cc00,16))
        check_bound(deadline)
        cdb=timed('cdb',lambda:mem(h,0x1cc10,12))
        check_bound(deadline)
        size=int.from_bytes(metadata[8:12],'little')
        direction=metadata[1]
        timed('pending_log',lambda:log('pending_context',context=ctx,
              metadata=metadata.hex(),cdb=cdb.hex(),length=size,direction=direction))
        check_bound(deadline)
        if metadata[0]&0x1e:
            raise RuntimeError('CC00 fault flags require OEM USB recovery; context not dispatched')
        kind=classify_cdb(cdb,size,direction,allow_own)
        return {'context':ctx,'kind':kind,'cdb':cdb,'length':size,
                'metadata':metadata,'direction':direction,
                'key':(ctx,bytes(metadata[4:8]),cdb)}
    finally:
        elapsed=time.monotonic()-started
        # Normal claims stay quiet. Include logfile open/write/close time so
        # a delayed log cannot be mistaken for a delayed USB control request.
        if elapsed>=0.1:
            log('claim_timing',context=ctx,elapsed_seconds=elapsed,
                phases_seconds=phases)

def require_idle_worker():
    if disk is None or (disk.thread is not None and disk.thread.is_alive()):
        raise RuntimeError('Idle TUR recovery requires no active Windows SPTI worker')

def revalidate_idle_tur(h,item,deadline):
    """Recheck a claimed idle TUR without popping another D03A context."""
    check_bound(deadline);require_idle_worker()
    metadata=item.get('metadata',b'');cdb=item.get('cdb',b'')
    if (item.get('kind')!='tur' or item.get('length')!=0 or
            item.get('direction')!=0 or cdb!=bytes(12) or len(metadata)!=16 or
            metadata[1]!=0 or metadata[8:12]!=bytes(4) or metadata[0]&0x1e or
            item.get('key')!=(item.get('context'),bytes(metadata[4:8]),cdb)):
        raise RuntimeError('Only an exact idle zero-data TUR may receive a fresh service budget')
    if read(h,0xc04c)!=item['context']:
        raise RuntimeError('Idle TUR context changed during acquisition')
    fresh_metadata=mem(h,0x1cc00,16)
    fresh_cdb=mem(h,0x1cc10,12)
    if (fresh_metadata!=metadata or fresh_cdb!=cdb or
            read(h,0xc04c)!=item['context']):
        raise RuntimeError('Idle TUR metadata, tag or CDB changed during acquisition')
    usb=read(h,0xd100);control=read(h,0xd114)
    phy=read(h,0xe014);task=read(h,0xe08c)
    check_bound(deadline);require_idle_worker()
    if usb&0x10 or control&1:
        raise RuntimeError('Idle TUR USB reset or busy state; no status sent')
    if CAPACITY_BLOCKS<=0 or not(phy&1) or not(task&0x40) or task&0xa9:
        raise RuntimeError('Idle TUR PHY/task is not ready; no status sent')

def verified_protocol(h,ctx,values):
    if read(h,0xc04c)!=ctx:
        raise RuntimeError('Context changed before protocol setup')
    for a,v in values:write(h,a,v)
    if read(h,0xc04c)!=ctx or any(read(h,a)!=v for a,v in values):
        raise RuntimeError('Queued protocol fields did not verify')

def translate_pending(h,item,deadline,watch_worker):
    check_bound(deadline,watch_worker)
    write(h,0xe01f,1);write(h,0xd1d0,item['context'])
    end=min(deadline,time.monotonic()+0.75)
    while read(h,0xd1d1)&0x80:
        check_bound(end,watch_worker);time.sleep(.002)
    for i,v in enumerate(item['length'].to_bytes(4,'little')):write(h,0xe188+i,v)

def service_tur(h,item,deadline,watch_worker):
    global PHYSICAL_LOCKED
    ctx=item['context']
    verified_protocol(h,ctx,((0xcc2f,0x40),(0xcc03,0xc0),(0xcc0e,2),(0xcc2a,1)))
    # 6097 sets E03C from CC2A before translation, clearing it after issue.
    write(h,0xe03c,1)
    try:
        translate_pending(h,item,deadline,watch_worker)
        check_bound(deadline,watch_worker)
        write(h,0xe024,1);write(h,0xe08c,0x80)
    finally:
        write(h,0xe03c,0)
    end=min(deadline,time.monotonic()+2.0)
    last=None;status_received=False
    while True:
        check_bound(end,watch_worker)
        usb_gate(h,end,watch_worker)
        sample={'event':read(h,0xe000),'status_event':read(h,0xe030),
                'task':read(h,0xe08c),'error':read(h,0xe08d),'phy':read(h,0xe014)}
        if sample!=last:log('tur_sample',context=ctx,**sample)
        last=sample
        if sample['event']&0x10 or not(sample['phy']&1):
            raise RuntimeError('TUR transport failure; no SCSI status fabricated')
        if sample['status_event']&1:
            status_received=True
            before=sample['task']
            write(h,0xe030,1)
            sample['task']=read(h,0xe08c);sample['error']=read(h,0xe08d)
            log('nodata_status_ack',context=ctx,before=before,after=sample['task'],error=sample['error'],fis=mem(h,0x1e100,20).hex())
        if status_received and not(sample['task']&0x80):break
        time.sleep(.002)
    status=1 if sample['task']&1 else 0
    if item['kind']=='prevent_allow' and not status:
        PHYSICAL_LOCKED=bool(item['cdb'][4])
        log('physical_tray_lock',locked=PHYSICAL_LOCKED)
    if read(h,0xc04c)!=ctx:raise RuntimeError('TUR completion context changed')
    if status:
        write(h,0xcc32,sample['task']);write(h,0xcc33,sample['error'])
    # 748C -> 6622 -> 6ECD -> 744F. No data buffer is routed or reset.
    write(h,0xcc0e,2);write(h,0xcc0f,0)
    residual=mem(h,0x1cc08,4)
    if residual!=bytes(4):raise RuntimeError('No-data context has a nonzero residual')
    for i,v in enumerate(residual):write(h,0xd11c+i,v)
    check_bound(deadline,watch_worker);usb_gate(h,deadline,watch_worker)
    write(h,0xd138,ctx|0x80)
    write(h,0xd117,status);write(h,0xd114,4)
    write(h,0xe030,1)
    log('queued_tur_csw',context=ctx,status=status,task=sample['task'],error=sample['error'])
    # A physical no-data auth command may finish SPTI immediately after CSW.
    # There is no new command/status to protect after this point.
    settle_csw(h,deadline,False)

def service_data_in(h,item,deadline,watch_worker):
    ctx=item['context'];size=item['length']
    verified_protocol(h,ctx,((0xcc03,0xd0),(0xcc0e,0x40),(0xcc2a,0)))
    # A previous command must have reached normal USB completion before entry.
    # No C98B reset occurs while USB is draining. The verified bit6 completion
    # branch below flushes only after both SATA and USB completion.
    write(h,0xc980,0)
    for i,v in enumerate(bytes.fromhex('0000000000000801')):write(h,0xc984+i,v)
    translate_pending(h,item,deadline,watch_worker)
    check_bound(deadline,watch_worker)
    # With the CPU held, serialize using the actual completion events below.
    # The ROM's adjacent synthetic E08C=80 write becomes a separate, slow USB
    # transaction here and can overwrite already-returned status on fast CDBs.
    # Do not rewrite the device status after issuing this data-in command.
    write(h,0xe024,1)
    write(h,0xc980,0);write(h,0xc988,5);write(h,0xd138,ctx);write(h,0xc988,0x45)
    log('queued_bulk_armed',context=ctx,kind=item['kind'],length=size)
    sata_done=False;usb_done=False;scsi_failed=False;last=None;end=min(deadline,time.monotonic()+8.0)
    while True:
        check_bound(end,watch_worker)
        sample={'event':read(h,0xe000),'task':read(h,0xe08c),'error':read(h,0xe08d),
                'usb_event':read(h,0xd100),'control':read(h,0xd114),'phy':read(h,0xe014)}
        if sample!=last:log('queued_bulk_sample',context=ctx,kind=item['kind'],**sample)
        last=sample
        if sample['event']&0x10 or not(sample['phy']&1):
            raise RuntimeError('Queued data command transport failure')
        if sample['usb_event']&0x10:
            raise RuntimeError('Exceptional USB data path; no successful CSW fabricated')
        if not sata_done and sample['event']&0x80:
            if sample['task']&0x80:
                # Status and event are separate USB register reads. A very
                # fast command can expose its completion bit before the task
                # status snapshot clears BSY. Wait within the same deadline;
                # do not release buffers or emit status until BSY is clear.
                time.sleep(.002)
                continue
            scsi_failed=bool(sample['task']&1)
            if (scsi_failed and item['kind'] not in ('mode_sense6','read_blocks','read_capacity')
                    and item['kind'] not in AUTH_DATA_IN_KINDS):
                raise RuntimeError('Unexpected SATA data-command error')
            # ROM1F24..1F8E: terminate the SATA buffer and retain actual task
            # status. The observed ATAPI error path leaves sense in the drive.
            write(h,0xc980,0);write(h,0xc988,0x40);read(h,0xc988);write(h,0xe165,0x20)
            if scsi_failed:write(h,0xcc32,sample['task'])
            write(h,0xe030,1);write(h,0xe000,0xff)
            sata_done=True
        # 2E44 accepts bit6 independently of bit3. Both branches remain bounded
        # and require actual SATA completion before any buffer flush or CSW.
        # A completed ATAPI command error uses failed CSW and real drive sense.
        usb_done=bool(sample['usb_event']&0x48) and not(sample['control']&1)
        if sata_done and usb_done:break
        time.sleep(.002)
    check_bound(deadline,watch_worker)
    if read(h,0xc04c)!=ctx:raise RuntimeError('Data completion context changed')
    bit6=bool(sample['usb_event']&0x40)
    write(h,0xd100,0x48 if bit6 else 8)
    source=0x1d134 if bit6 else 0x1cc08
    residual=mem(h,source,4);residual_count=int.from_bytes(residual,'little')
    if residual_count>size:raise RuntimeError('Residual exceeds queued allocation')
    log('queued_bulk_residual',context=ctx,kind=item['kind'],bytes=residual_count,
        raw=residual.hex(),source=hex(source),completion='bit6' if bit6 else 'bit3',
        current_context_length=mem(h,0x1cc08,4).hex(),usb_control=read(h,0xd114))
    if not scsi_failed and item['kind'] in ('read_capacity','read_blocks') and residual_count:
        raise RuntimeError('Fixed-size capacity/sector transfer has nonzero residual; no success CSW sent')
    for i,v in enumerate(residual):write(h,0xd11c+i,v)
    if bit6:
        # Exact 2EA6..2EC8 termination after BOTH SATA and USB bit6 completion.
        # This is the only queued-data path allowed to reset its completed buffer.
        write(h,0xc980,0);write(h,0xc98b,1);read(h,0xc98b)
        write(h,0xd115,2);read(h,0xd115)
        write(h,0xc98b,1);read(h,0xc98b)
        write(h,0xc987,0);write(h,0xc988,0);read(h,0xc988)
    usb_gate(h,deadline,watch_worker);check_bound(deadline,watch_worker)
    write(h,0xd117,1 if scsi_failed else 0);write(h,0xd114,4)
    if bit6:write(h,0xd100,8)
    log('queued_data_csw',context=ctx,kind=item['kind'],status=int(scsi_failed),residual=residual_count)
    settle_csw(h,deadline,False)

def service_data_out_auth(h,item,deadline,watch_worker):
    """Completed USB OUT -> SATA path, restricted to CSS auth packets.

    ROM2B21..2B37 supplies protocol E0 / CC0F10 / buffer1 route63.
    ROM71FD supplies D130=context before C988=63. ROM2FFD..3051 consumes
    USB OUT completion; ROM203F..2148 finishes SATA and sends actual status.
    ROM2FA4..3051 also permits bit5 once OUT is inactive. Only its D11A=0
    subset is supported; active-OUT termination and nonzero D11A remain faults.
    """
    ctx=item['context'];size=item['length']
    if (item['kind'] not in AUTH_DATA_OUT_KINDS or
            validate_auth_cdb(item['cdb'],size,'out') != item['kind']):
        raise RuntimeError('Only exact SEND KEY challenge/key2 may use USB OUT')
    check_bound(deadline,watch_worker)
    usb_gate(h,deadline,watch_worker)
    if read(h,0xd118)&1 or read(h,0xd100)&0x24:
        raise RuntimeError('Unowned USB OUT activity/completion before authentication')
    verified_protocol(h,ctx,((0xcc03,0xe0),(0xcc0e,0),(0xcc0f,0x10),(0xcc2a,0)))
    write(h,0xc980,1)
    for i,v in enumerate(bytes.fromhex('0000000000000801')):write(h,0xc984+i,v)
    translate_pending(h,item,deadline,watch_worker)
    check_bound(deadline,watch_worker)
    write(h,0xe024,1);write(h,0xe08c,0x80)
    write(h,0xd130,ctx);write(h,0xc980,1);write(h,0xc988,0x63)
    log('auth_out_armed',context=ctx,kind=item['kind'],length=size)
    end=min(deadline,time.monotonic()+8.0);last=None
    usb_bit5_done=False;residual=None;residual_count=None

    def sample_state():
        nonlocal last
        value={'event':read(h,0xe000),'task':read(h,0xe08c),
               'error':read(h,0xe08d),'usb_event':read(h,0xd100),
               'out_control':read(h,0xd118),'out_status':read(h,0xd11a),
               'usb_control':read(h,0xd114),'phy':read(h,0xe014),
               'sata_status_e040':read(h,0xe040)}
        # Preserve the actual fault snapshot before any guard raises. D11A
        # and D118 distinguish the ROM's bit5 branches at2F30..2FA4.
        if value!=last:log('auth_out_sample',context=ctx,kind=item['kind'],**value)
        last=value
        if value['event']&0x10 or not value['phy']&1:
            raise RuntimeError('Authentication OUT SATA transport failure')
        if value['usb_event']&0x10:
            raise RuntimeError('Authentication OUT USB reset path is outside scope')
        if value['usb_event']&0x20 and value['out_status']:
            raise RuntimeError('Authentication OUT bit5 with nonzero D11A is outside scope')
        if read(h,0xc04c)!=ctx:
            raise RuntimeError('Authentication OUT context changed')
        return value

    while True:
        check_bound(end,watch_worker)
        sample=sample_state()
        if sample['usb_event']&0x20 and not usb_bit5_done and not sample['out_control']&1:
            # ROM2F71..2FA9 waits for D118.bit0 clear, then acknowledges24.
            # ROM2FC9..3051 marks USB complete and waits for SATA separately;
            # do not require SATA completion before acknowledging this event.
            # Preserve the hardware OUT byte count explicitly in our CSW.
            residual=mem(h,0x1d12c,4);residual_count=int.from_bytes(residual,'little')
            if residual_count>size:
                raise RuntimeError('Authentication OUT residual exceeds parameter length')
            write(h,0xd100,0x24)
            for i,v in enumerate(residual):write(h,0xd11c+i,v)
            usb_bit5_done=True
            log('auth_out_bit5_completed',context=ctx,kind=item['kind'],
                residual=residual_count,out_status=sample['out_status'],
                out_control=sample['out_control'],sata_event=sample['event'])
        # Acknowledged bit5 replaces only the USB completion evidence. Fresh
        # SATA bit2 and inactive OUT remain mandatory before buffer release.
        if sample['event']&4 and (usb_bit5_done or sample['usb_event']&4) and not sample['out_control']&1:
            break
        time.sleep(.002)
    # ROM3004..302C: preserve the actual USB OUT residual before releasing its
    # buffer. Unlike IN, this direction uses D12C..12F, not D134..137.
    if not usb_bit5_done:
        residual=mem(h,0x1d12c,4);residual_count=int.from_bytes(residual,'little')
        if residual_count>size:
            raise RuntimeError('Authentication OUT residual exceeds parameter length')
        write(h,0xd100,4)
        for i,v in enumerate(residual):write(h,0xd11c+i,v)
    # ROM2055..207B, ordinary OUT branch (E8.bit4 clear). USB OUT and SATA
    # data completion are required above; no buffer reset runs during transfer.
    write(h,0xc980,1);write(h,0xe165,0x40);read(h,0xe165)
    write(h,0xd119,2);read(h,0xd119)
    write(h,0xc987,0);write(h,0xc988,0);read(h,0xc988)
    # ROM207C checks returned status AFTER releasing the completed data path.
    # A still-BUSY device never receives a successful CSW.
    while True:
        check_bound(end,watch_worker)
        sample=sample_state()
        if not sample['task']&0x88:break
        time.sleep(.002)
    status=int(bool(sample['task']&1))
    # ROM20F2..2135 reaches good status only with E040=0 (and SFRF5.bit0
    # clear). No host alias for F5 is established; never infer one here.
    if not status and sample['sata_status_e040']:
        raise RuntimeError('Authentication OUT E040 is nonzero; no good CSW sent')
    if residual_count and not status:
        raise RuntimeError('Successful authentication OUT has a nonzero residual')
    if status:
        write(h,0xcc32,sample['task']);write(h,0xcc33,sample['error'])
    usb_gate(h,deadline,watch_worker);check_bound(deadline,watch_worker)
    write(h,0xd117,status);write(h,0xd114,4)
    write(h,0xe030,1);write(h,0xe000,6)
    log('auth_out_csw',context=ctx,kind=item['kind'],status=status,
        residual=residual_count,task=sample['task'],error=sample['error'],
        completion='bit5' if usb_bit5_done else 'bit2')
    settle_csw(h,deadline,False)

def service_bridge_nodata(h,item,deadline,watch_worker):
    """Adapter-level readiness/removal policy for our read-only virtual bridge.

    Media is fixed for a reader session. Real data reads still reach the DVD;
    any data-command failure ends the session. These status/control requests
    do not claim a new physical SATA command or a mechanical tray lock.
    """
    ctx=item['context']
    if CAPACITY_BLOCKS<=0 or not(read(h,0xe014)&1) or read(h,0xe08c)&0x80:
        raise RuntimeError('Bridge is not idle/ready for cached media status')
    if item['kind'] not in ('tur','prevent_allow') or item['length']!=0:
        raise RuntimeError('Invalid bridge housekeeping command')
    verified_protocol(h,ctx,((0xcc03,0xc0),(0xcc0e,2),(0xcc0f,0),(0xcc2a,1)))
    if mem(h,0x1cc08,4)!=bytes(4):raise RuntimeError('No-data request has a payload')
    for a in range(0xd11c,0xd120):write(h,a,0)
    usb_gate(h,deadline,watch_worker);check_bound(deadline,watch_worker)
    write(h,0xd138,ctx|0x80);write(h,0xd117,0);write(h,0xd114,4)
    log('bridge_nodata_csw',context=ctx,kind=item['kind'],status=0,
        media_fixed_for_session=True,physical_sata_command=False,
        virtual_prevent=bool(item['cdb'][4]) if item['kind']=='prevent_allow' else None)
    settle_csw(h,deadline,False)

def service_pending(h,item,deadline,watch_worker,seen):
    check_bound(deadline,watch_worker);usb_gate(h,deadline,watch_worker)
    if item['key'] in seen:
        log('duplicate_pending_context',context=item['context'],opaque_tag=item['key'][1].hex(),cdb=item['cdb'].hex())
        raise RuntimeError('Serviced context/tag/CDB reappeared; no duplicate command or CSW sent')
    if read(h,0xc04c)!=item['context']:raise RuntimeError('Pending context changed')
    # Retire only previous IN completion flags before the next queued command.
    write(h,0xd100,0x48)
    for a in (0xe008,0xe030,0xe031,0xe000,0xe001):write(h,a,0xff)
    if item['kind'] in AUTH_DATA_OUT_KINDS:service_data_out_auth(h,item,deadline,watch_worker)
    elif item['kind']=='invalidate_agid':service_tur(h,item,deadline,watch_worker)
    elif item['kind'] in ('tur','prevent_allow'):service_bridge_nodata(h,item,deadline,watch_worker)
    else:service_data_in(h,item,deadline,watch_worker)
    # Context slots and opaque host tags are reusable after completion. Keep
    # only the immediately preceding completed key; an entire busy period can
    # exceed the hardware's 32-context ring during ordinary Windows probing.
    seen.clear();seen.add(item['key'])


# One hardware owner per process; all requests are serialized on its thread.
h=None;issued=False;original={};mode_saved={};disk=None;context=None
CAPACITY_BLOCKS=0
MAX_BLOCKS=16
PHYSICAL_LOCKED=False

def open_transport():
    global h,issued,original,mode_saved,disk,context,CAPACITY_BLOCKS
    target=api.discover();log('target',**target);disk=ScsiRead();log('scsi_target',**disk.identity);h=api.Hub(target);h.hold();time.sleep(.02)
    headers=[mem(h,0,16) for _ in range(3)]
    log('rom_precondition',reads=[value.hex() for value in headers],expected=api.HEADER.hex())
    # First post-hold response can contain stale leading bytes. Require two
    # consecutive exact subsequent reads; USB identity is independently checked.
    if headers[-2:]!=[api.HEADER,api.HEADER]:raise RuntimeError('Unexpected ROM header')
    h.command(0x8201,0);h.command(0x8101,0)
    one=h.command(0xba03,length=1)
    log('one_byte_reader_precondition',data=one.hex())
    if one!=api.HEADER[:1]:raise RuntimeError('One-byte reader does not match verified ROM')
    log('initial',state=state(h))
    write(h,0xe013,0);write(h,0xe010,8)
    # Base engine setup from ROM62B3..62E8, retaining the proven E010=08 link setting.
    write(h,0xe007,0x40);write(h,0xe028,0xff);write(h,0xe020,3)
    write(h,0xe166,read(h,0xe166)&0xfc)
    for a in range(0xe03c,0xe040):write(h,a,0)
    write(h,0xe168,read(h,0xe168)|0x0f)
    write(h,0xe013,0x80);time.sleep(.02)
    # ROM5A79..5A9E event setup preceding the link request.
    write(h,0xe034,0x24);write(h,0xe002,0x87)
    for a in (0xe008,0xe030,0xe031,0xe000,0xe001,0xe028,0xe08c):write(h,a,0xff)
    write(h,0xe00c,(read(h,0xe00c)&0x7f)|8)
    write(h,0xe010,read(h,0xe010)|1);write(h,0xe034,read(h,0xe034)|1)
    ready=False
    for _ in range(30):
        sig=mem(h,0x1e090,10);s=state(h)
        if s['phy']&1 and not s['task']&0x81 and sig[:3]==bytes.fromhex('0114eb') and sig[8]==1:
            ready=True;break
        time.sleep(.1)
    log('link',state=s,signature=sig.hex(),ready=ready)
    if not ready:raise RuntimeError('ATAPI link prerequisites not met')
    write(h,0xe034,read(h,0xe034)&0xfe)
    for a in (0xe008,0xe030,0xe031,0xe000,0xe001):write(h,a,0xff)
    # ROM 6CC8..6CE2 initializes just the buffer slot used by IDENTIFY.
    write(h,0xc980,1)
    log('buffer_before',registers=mem(h,0x1c984,8).hex())
    for i,v in enumerate(bytes.fromhex('0000000000000801')):write(h,0xc984+i,v)
    log('buffer_initialized',registers=mem(h,0x1c984,8).hex())


    context=read(h,0xc04c)
    original={a:read(h,a) for a in FIELDS};mode_saved={a:read(h,a) for a in MODE}
    log('context_before',selector=context,metadata=mem(h,0x1cc00,16).hex())
    for a,v in ((0xe069,0xff),(0xe06a,0xff),(0xe06c,1),(0xd146,7),(0xd147,mode_saved[0xd147]|8)):write(h,a,v)
    inquiry=packet(h,context,bytes.fromhex('120000002400000000000000'),36,'inquiry')
    if not inquiry['ok']:raise RuntimeError('Optical inquiry failed')
    d=inquiry['data']
    if d[0]&31!=5 or d[8:16].strip()!=b'HL-DT-ST' or d[16:32].strip()!=b'DVDRAM GU40N':
        raise RuntimeError('Optical identity mismatch; no disc command sent')
    log('optical_identity',vendor=d[8:16].decode().strip(),product=d[16:32].decode().strip(),revision=d[32:36].decode().strip())
    capacity=None
    for attempt in range(3):
        r=packet(h,context,bytes.fromhex('250000000000000000000000'),8,'read_capacity_'+str(attempt))
        if r['ok']:capacity=r['data'];break
        sr=sense(h,context)
        if not sr['ok'] or sr.get('sense_format') not in (0x70,0x71,0x72,0x73):break
        if sr.get('sense_key')==6:continue
        if sr.get('sense_key')==2 and sr.get('asc')==4:time.sleep(2);continue
        break
    if capacity is None:raise RuntimeError('Disc capacity unavailable; see sense response')
    last_lba=int.from_bytes(capacity[:4],'big');block_size=int.from_bytes(capacity[4:],'big')
    if last_lba==0xffffffff:raise RuntimeError('Capacity overflow sentinel; not a verified disc size')
    info={'last_lba':last_lba,'blocks':last_lba+1,'block_size':block_size,'bytes':(last_lba+1)*block_size}
    log('disc_capacity',**info)
    Path('outputs/initio/disc-capacity.json').write_text(json.dumps(info,indent=2))
    if last_lba<16 or last_lba==0xffffffff or block_size not in (512,1024,2048,2352,4096):
        raise RuntimeError('Unexpected capacity; no sector request sent')


    # Restore the previous synthetic context before servicing actual queued work.
    if read(h,0xc04c)!=context:
        write(h,0xc04c,context)
        if read(h,0xc04c)!=context:raise RuntimeError('Pre-bulk selector restoration failed')
    mismatches=restore_fields(h,original)
    log('pre_bulk_context_restored',mismatches=mismatches)
    if mismatches:raise RuntimeError('Pre-bulk synthetic context restoration failed')
    original={}
    if block_size!=2048:raise RuntimeError('Fixed Windows probe requires 2048-byte blocks')
    CAPACITY_BLOCKS=last_lba+1
    if read(h,0xd100)&0x40:raise RuntimeError('Unowned USB IN completion before service')
    usb_gate(h)
    write(h,0xd045,mode_saved[0xd045]|0x80)
    log('live_reader_initialized',blocks=CAPACITY_BLOCKS)
    return info

def wait_for_worker():
    # Called only on the non-daemon hardware owner. A driver timeout is not
    # evidence that its synchronous DeviceIoControl thread has actually exited.
    worker = getattr(disk, 'thread', None)
    while worker is not None and worker.is_alive():
        worker.join(.25)


def close_transport():
    global h, disk, issued, original, mode_saved, context, CAPACITY_BLOCKS
    errors = []

    def report(stage, **values):
        try:
            log(stage, **values)
        except BaseException as exc:
            errors.append('cleanup logging: ' + str(exc))

    def attempt(stage, operation):
        try:
            operation()
        except BaseException as exc:
            errors.append(stage + ': ' + str(exc))
            report(stage + '_error', message=str(exc))

    def restore_context():
        if read(h, 0xc04c) != context:
            write(h, 0xc04c, context)
            if read(h, 0xc04c) != context:
                raise RuntimeError('Context selector restoration failed; original fields not written into different context')
        mismatches = restore_fields(h, original)
        report('context_restoration', mismatches=mismatches)
        if mismatches:
            raise RuntimeError('Context restoration did not verify: ' + repr(mismatches))

    def restore_modes():
        mismatches = restore_fields(h, mode_saved)
        report('mode_restoration', mismatches=mismatches)
        if mismatches:
            raise RuntimeError('Mode restoration did not verify: ' + repr(mismatches))

    def clear_packet():
        write(h, 0xe165, 0x20); write(h, 0xc980, 1)
        write(h, 0xc98b, 1); read(h, 0xc98b); write(h, 0xc988, 0)
        report('queue_cleanup', state=state(h))

    def unlock_tray():
        global PHYSICAL_LOCKED
        from atapi_media_control import unlock
        worker=getattr(disk,'thread',None)
        # Never insert another SATA command into an outstanding own request.
        # If a failing request is still pending, OEM CPU resume takes priority.
        if worker is None or not worker.is_alive():
            deadline=time.monotonic()+5;seen=set();serviced=0
            while read(h,0xc051)&0x10 and serviced<32:
                item=claim_pending(h,False,deadline)
                if item is None:break
                service_pending(h,item,deadline,False,seen);serviced+=1
        result=unlock(h,sys.modules[__name__])
        report('physical_tray_unlock',**result)
        if result['ok']:PHYSICAL_LOCKED=False
        elif not result['restored']:
            raise RuntimeError('Tray-unlock context did not restore')
        else:
            report('physical_tray_unlock_deferred',reason=result['failure'],locked=PHYSICAL_LOCKED)

    try:
        if h:
            if issued:
                attempt('queue_cleanup', clear_packet)
            if PHYSICAL_LOCKED:
                attempt('tray_unlock', unlock_tray)
            if original:
                attempt('context_restoration', restore_context)
            if mode_saved:
                attempt('mode_restoration', restore_modes)
    finally:
        try:
            if h:
                attempt('spi_mode', h.spi_mode)
                # Resume is attempted even if an earlier restore or log failed.
                attempt('cpu_resume', h.resume)
        finally:
            try:
                if h:
                    attempt('hub_close', h.close)
            finally:
                # Never release the owning mutex with an outstanding IOCTL.
                # The public reader.close() can report incomplete cleanup while
                # this background owner keeps waiting in short intervals.
                wait_for_worker()
                if disk:
                    attempt('disk_close', disk.close)
                h = None; disk = None; issued = False
                original = {}; mode_saved = {}; context = None
                CAPACITY_BLOCKS = 0
                report('finished', cleanup_errors=errors.copy(),physical_tray_may_be_locked=PHYSICAL_LOCKED)
    if errors:
        raise RuntimeError('Transport cleanup failed: ' + '; '.join(errors))
