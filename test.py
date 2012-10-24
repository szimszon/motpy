# -*- coding: utf-8 -*-


class userInfo(object):
    def __init__(self, config, log, username):
        self.config = config
        self.log = log
        self.username = username

    def getInfo(self):
        return dict(pin='1234',
                            secret='1234567890123456',
                            offset=0)

    def setLastOtp(self, otp):
        return True
