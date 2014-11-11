class SIPParser():
    
    def __init__(self, data=None):
        self.method = ''
        self.call_id = ''
        self.has_sdp = False
        self.c_ip = ''
        self.m_port = ''
        if data != None:
            self.parse(data)

    def parse(self, data):
        fields = data.split('\x0d\x0a')
        state = 0
        self.has_sdp = False
        self.request = fields[0]
        for f in fields:
            if f.startswith('Call-ID: '):
                self.call_id = f[9:f.find('@')]
            elif state == 0 and len(f) == 0:
                state = 1
            elif state == 1 and f.startswith('v=0'):
                state = 2
                self.has_sdp = True
            elif state == 2 and f.startswith('c='):
                self.c_ip = f[f.rfind(' ')+1:]
            elif state == 2 and f.startswith('m=') and self.m_port == '':
                start = f.find(' ')+1
                end = f.find(' ', start)
                self.m_port = f[start:end]
