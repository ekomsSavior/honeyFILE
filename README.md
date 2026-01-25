# honeyFILE
honeyPOT FIle booby-trap 

dependencies:

```bash
sudo apt update
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
```
clone in:

```bash
git clone https://github.com/ekomsSavior/honeyFILE.git
cd honeyFILE
```

initaite honeyFILE:

```bash
python3 honeyfile.py init random                                                                                                 
sudo python3 honeyfile.py arm
sudo auditctl -l | grep honeyfile
```
If you want, paste the output of:

```bash
python3 honeyfile.py status
```
