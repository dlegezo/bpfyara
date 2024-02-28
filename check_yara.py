#!/usr/bin/python3  
import pyfanotify
import select
import yara

def subscribe_exec():
    notifier = pyfanotify.Fanotify()
    notifier.mark("/", is_type="fs")
    notifier.start()
    client = pyfanotify.FanotifyClient(notifier, path_pattern='*')

    poller = select.poll()
    poller.register(client.sock.fileno(), select.POLLIN)
    try:
        while poller.poll():
            desc = {}
            for event in client.get_events():
                # 4129 - access|open|open_exec, 33 - access|open to add .so checks
                if (event.ev_types == 4129):
                    check_yara(str(event.path), event.pid) 
                event.ev_types = pyfanotify.evt_to_str(event.ev_types)
                desc.setdefault(event.path, []).append(event)
    except PermissionError:
        print("Access denied", event.ev_types)
    finally:
        print("Monitoring stopped due to exception")

    client.close()
    notifier.stop()

def malware_handler_mem(data):
    print("Mythic/poseidon found in memory", data)

def malware_handler_disk(data):
    print("Mythic/poseidon found on disk", data)

def check_yara(path: str, pid: int):
    print("checking", path, pid)
    rules = yara.compile("/home/dlegezo/poseidon.yara")
    try:
        matches = rules.match(pid=pid, callback=malware_handler_mem, which_callbacks=yara.CALLBACK_MATCHES)
        matches = rules.match(path[2:-1], callback=malware_handler_disk, which_callbacks=yara.CALLBACK_MATCHES)
    except yara.Error as e:
        print("Yara error", e) 

def main():
    subscribe_exec()    

if __name__ == "__main__":
    main()