# -*- coding: utf-8 -*-


class userInfo(object):
    '''
        userInfo class to get and set info or set last matched otp
    '''
    def __init__(self, config, userinfostore):
        self.config = config
        self.log = self.config.log
        self.valid = True
        self.username = userinfostore.get_username()
        self.eusername = userinfostore.get_eusername()
        self.decrypt = userinfostore.crypt.decrypt
        try:
            from pwd import getpwnam
            self.userid = getpwnam(self.username).pw_uid
        except:
            import traceback
            self.log.debug('There is no userid! Traceback: %s' % (
                                               str(traceback.format_exc())), 1)
            self.userid = None
            self.valid = False
        try:
            from grp import getgrnam
            self.groupid = getgrnam(self.username).gr_gid
        except:
            import traceback
            self.log.debug('There is no groupid! Traceback: %s' % (
                                               str(traceback.format_exc())), 1)
            self.groupid = None
            self.valid = False
        import os
        try:
            cdir = self.config.get('homedir', 'dir')
        except:
            cdir = os.path.join('.config', 'motpy')
        try:
            self.motp_dir = os.path.join(getpwnam(self.username).pw_dir, cdir)
            self.lastotp_file = os.path.join(self.motp_dir, 'lastotp.pickle')
            self.db_file = os.path.join(self.motp_dir, 'motpy.pickle')
        except:
            import traceback
            self.log.debug('There is no userdata dir! Traceback: %s' % (
                                               str(traceback.format_exc())), 1)
            self.motp_dir = None
            self.lastopt_file = None
            self.db_file = None
            self.valid = False

    def isValidDbForUser(self):
        '''
            Return true if there is a motp set already
        '''
        import os
        if not self.valid:
            return False
        if os.access(self.db_file, os.R_OK):
            return True
        return False

    def checkPath(self, path):
        '''
            Check if path exist and has right ownership and rights
        '''
        import os
        ret = True

        #
        # Check exists
        # #############
        if not os.access(path, os.R_OK):
            self.log.log("ERR: %s path doesn't exist or not readable" % path)
            return False
        #
        # Check mode
        # ###########
        fstat = os.lstat(path)
        if fstat.st_mode != 16832 and fstat.st_mode != 33152:
            self.log.log('ERR: %s path has invalid mode' % path)
            ret = False

        #
        # Check owner
        # ############
        from pwd import getpwnam
        if fstat.st_uid != getpwnam(self.username)[2]:
            self.log.log('ERR: %s path has invalid ownership' % path)
            ret = False
        return ret

    def getAllLastOtps(self):
        '''
            Return the list of saved Otps or None if something went wrong
        '''

        if not self.valid:
            return None
        #
        # Pre checkings - path
        # #####################
        if not self.checkPath(self.motp_dir) or \
            not self.checkPath(self.lastotp_file):
            return None

        import cPickle
        try:
            flastotp = open(self.lastotp_file, 'rb')
            picklelastotp = dict(cPickle.load(flastotp))
            flastotp.close()
        except:
            import traceback
            self.log.log('ERR: Something went wrong with lastotp: %s' % \
                         str(traceback.format_exc()))
            return None
        self.log.debug('DEBUG: picklelastotp: [[%s]]' % str(picklelastotp), 10)
        return dict(picklelastotp)

    def getLastOtps(self):
        '''
            Get the last valid otps for the user
        '''
        lastotps = self.getAllLastOtps()
        if not lastotps:
            return None
        ret = list()
        try:
            for i in lastotps.keys():
                if self.decrypt(i) == self.username:
                    ret = list(lastotps[i])
                    break
        except:
            ret = list()
        return ret

    def getAllInfo(self):
        '''
            get all info dict
        '''

        #
        # Pre checkings - path
        # #####################
        if not self.valid:
            return None
        if not self.checkPath(self.motp_dir) or \
            not self.checkPath(self.db_file):
            return None

        import cPickle
        try:
            fuserinfo = open(self.db_file, 'rb')
            pickleuserinfo = dict(cPickle.load(fuserinfo))
            fuserinfo.close()
        except:
            import traceback
            self.log.log('ERR: Something went wrong with userinfo db: %s' % \
                         str(traceback.format_exc()))
            return None
        return pickleuserinfo

    def getInfo(self):
        '''
            get all info dict
        '''
        userinfo = dict(pin=None,
                        secret=None,
                        offset=None)
        allinfo = self.getAllInfo()
        try:
            for i in allinfo.keys():
                if self.decrypt(i):
                    userinfo = dict(allinfo[i])
                    break
        except:
            import traceback
            print traceback.format_exc()
            return dict(pin=None,
                                secret=None,
                                offset=None)
        return userinfo

    def setLastOtp(self, otp):
        '''
            store the matched otp that it can't be used next
        '''
        lastotp = self.getAllLastOtps()
        self.log.debug('DEBUG: before lastotp: [[%s]] otp: <%s>' % (
                                            str(lastotp),
                                            str(otp)), 10)
        if not self.valid:
            return None
        if not lastotp:
            lastotp = dict()

        username_in_lastopt = None
        for i in lastotp:
            if self.decrypt(i) == self.username:
                username_in_lastopt = i
                break
        if not username_in_lastopt:
            lastotp[self.eusername] = list()
            username_in_lastopt = self.eusername
        lastotp[username_in_lastopt].insert(0, otp)
        lastotp[username_in_lastopt] = lastotp[username_in_lastopt][:10]
        self.log.debug('DEBUG: after lastotp: [[%s]]' % str(lastotp), 10)

        import cPickle
        try:
            flastotp = open(self.lastotp_file, 'wb')
            cPickle.dump(lastotp, flastotp)
            flastotp.close()
        except:
            import traceback
            self.log.log("ERR: Can't store lastotps in file: %s" % \
                          str(traceback.format_exc()))
            return None

        return True

    def setUserInfo(self, pin, secret=None, offset=None):
        '''
            set the userinfo
        '''
        import os

        if not self.valid:
            return False

        #
        # Check or create motp config dir
        # ################################
        if not os.access(self.motp_dir, os.R_OK):
            try:
                os.makedirs(self.motp_dir, 0700)
                os.chown(self.motp_dir, self.userid, self.groupid)
            except:
                import traceback
                self.log.log(
                             "ERR: Something went wrong with" + \
                             " %s path creating! Traceback: %s" % (
                                self.motp_dir, str(traceback.format_exc())
                                )
                             )
                return False

        #
        # Check or create lastotp database
        # #################################
        if not os.access(self.lastotp_file, os.R_OK):
            import cPickle
            try:
                flastotp = open(self.lastotp_file, 'wb')
                cPickle.dump(list(), flastotp)
                flastotp.close()
            except:
                import traceback
                self.log.log("ERR: Can't inicialise lastotps %s file: %s" % (
                                            self.lastotp_file,
                                            str(traceback.format_exc())
                                            )
                             )
                return False
            try:
                os.chmod(self.lastotp_file, 0600)
                os.chown(self.lastotp_file, self.userid, self.groupid)
            except:
                import traceback
                self.log.log("ERR: Something went wrong with" + \
                             " %s lastotp inicialization! Traceback: %s" % (
                                            self.lastotp_file,
                                            str(traceback.format_exc())
                                            )
                             )
                return False

        #
        # Check or create motp database
        # ###############################
        if not os.access(self.db_file, os.R_OK):
            import cPickle
            try:
                fdb = open(self.db_file, 'wb')
                cPickle.dump(dict(), fdb)
                fdb.close()
            except:
                import traceback
                self.log.log("ERR: Can't inicialise motp db %s file: %s" % (
                                                self.db_file,
                                                str(traceback.format_exc())
                                                )
                             )
                return False
            try:
                os.chmod(self.db_file, 0600)
                os.chown(self.db_file, self.userid, self.groupid)
            except:
                import traceback
                self.log.log("ERR: Something went wrong with" + \
                             " %s motp db inicialization! Traceback: %s" % (
                                                self.db_file,
                                                str(traceback.format_exc())
                                                )
                             )
                return False


        #
        # Load existing motp database
        # ############################
        try:
            alluserinfo = dict(self.getAllInfo())
        except:
            return False
        username_in_alluserinfo = None
        for i in alluserinfo.keys():
            if self.decrypt(i) == self.username:
                username_in_alluserinfo = i
                break

        if not username_in_alluserinfo:
            username_in_alluserinfo = self.eusername
            alluserinfo[username_in_alluserinfo] = dict(offset=0)
        try:
            if not secret:
                secret = alluserinfo[username_in_alluserinfo]['secret']
        except:
            self.log.log("ERR: No secret is set for the account!")
            return False
        if not offset:
            offset = alluserinfo[username_in_alluserinfo]['offset']
        #
        # Replace with new motp database
        # ###############################
        alluserinfo[username_in_alluserinfo] = dict(pin=pin,
                                           secret=secret,
                                           offset=offset)
        import cPickle
        try:
            fdb = open(self.db_file, 'wb')
            cPickle.dump(alluserinfo, fdb)
            fdb.close()
        except:
            import traceback
            self.log.log("ERR: Can't store motp data in %s file: %s" % (
                                            self.db_file,
                                            str(traceback.format_exc())))
            return False

        return True
