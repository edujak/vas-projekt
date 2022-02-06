#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import spade
import pyshark
import socket
import subprocess
import datetime
import time
import nest_asyncio
from spade.agent import Agent
from spade.behaviour import OneShotBehaviour, PeriodicBehaviour

nest_asyncio.apply()

class Promatrac(Agent):
                
    class AnalizirajMrezu(PeriodicBehaviour):
        async def run(self):
            iface_name = 'enp0s3'
            capture = pyshark.LiveCapture(
                interface=iface_name,
            )
            try:
                for packet in capture.sniff_continuously():
                    try:
                        if socket.gethostbyaddr(packet.ip.dst)[0] == "edujak-VirtualBox":
                            pass
                        else:
                            hostic = socket.gethostbyaddr(packet.ip.dst)[0]
                            if hostic.endswith("fbcdn.net") or hostic.endswith("facebook.com"):
                                msg = spade.message.Message(
                                    to="posiljatelj@rec.foi.hr",
                                    body="Facebook"
                                )
                                await self.send(msg)
                                break
                            else:
                                print(hostic)
                    except socket.herror:
                        pass
            except AttributeError:
                pass

    async def setup(self):
        print("Promatrac: Pokrecem analizu mreznog prometa!")
        start_at = datetime.datetime.now()
        ponasanjeP = self.AnalizirajMrezu(period=10, start_at=start_at)
        self.add_behaviour(ponasanjeP)

class Sudac(Agent):
    class OkiniSkriptu(PeriodicBehaviour):
        async def run(self):
            msg = await self.receive(timeout=2)
            if msg:
                print(f"Sudac: Bio si na sljedećoj zabranjenoj stranici - {msg.body}")
                subprocess.call("./skripta.sh", shell=True)

    async def setup(self):
        print("Sudac: Pokrecem svoju prosudbu!")
        start_at = datetime.datetime.now()
        ponasanjeS = self.OkiniSkriptu(period=2, start_at=start_at)
        self.add_behaviour(ponasanjeS)

if __name__ == '__main__':
    promatrac = Promatrac("edujak@rec.foi.hr", "agent007")
    sudac = Sudac("posiljatelj@rec.foi.hr", "tajna")
    sudac.start()
    time.sleep(1)
    promatrac.start()
    input("Press ENTER to exit. \n")
    promatrac.stop()
    sudac.stop()
    spade.quit_spade()