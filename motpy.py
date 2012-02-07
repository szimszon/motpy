#!/usr/bin/env python
# -*- coding: utf-8 -*- 

class config( object ):
	'''
		Config object
	'''
	def __init__( self , log ):
		self.log = log
		#
		# timemargin - the time in minutes ± the code is validating against
		# ##################################################################
		self.timemargin = 3

		#
		# what backend module is in use
		# ##############################
		self.backend = 'homedir'

		#
		# config file
		# ##############################
		self.config = '/etc/security/motp.conf'


		#
		# salt (16,24 or 32 byte long)
		# ##############################
		self.salt = 'change........it'

		#
		# debug
		# ##############################
		self.debug = 0

		#
		# set an pin to a user
		# #####################
		self.set = False

		#
		# pinlenght - the lenght of the pin code
		# ##########
		self.pinlenght = 4

		#
		# secretlenght - the lenght of the secret code
		# ##########
		self.secretlenght = 16

		#
		# optparse
		# #########
		from optparse import OptionParser
		parser = OptionParser()
		parser.add_option( "-c", "--config",
										action = 'store',
										type = 'string',
										dest = "config",
										help = "config file (%s)" % self.config )
		parser.add_option( "-b", "--backend",
										action = 'store',
										type = 'string',
										dest = "backend",
										help = "backend name (%s)" % self.backend )
		parser.add_option( "-m", "--timemargin",
										action = 'store',
										type = 'int',
										dest = "timemargin",
										help = "timemargin in min (%d min.)" % self.timemargin )
		parser.add_option( "-s", "--salt",
										action = 'store',
										type = 'string',
										dest = "salt",
										help = "salt (%s)" % self.salt )
		parser.add_option( "-i", "--set",
										action = 'store_true',
										dest = "set",
										help = "set the pin and secret and offset" )
		parser.add_option( "-d", "--debug",
										action = 'store',
										type = 'int',
										dest = "debug",
										help = "debugging level (%d)" % self.debug )
		( self.cloptions, self.clargs ) = parser.parse_args()
		if self.cloptions.config:
			self.config = self.cloptions.config



		#
		# ConfigParser
		# #############
		from ConfigParser import ConfigParser
		self.configfile = ConfigParser()
		try:
			self.configfile.read( self.config )
			try:
				self.backend = self.configfile.get( 'main', 'backend' )
			except:
				pass
			try:
				self.timemargin = int( self.configfile.get( 'main', 'timemargin' ) )
			except:
				pass
			try:
				self.salt = self.configfile.get( 'main', 'salt' )
			except:
				pass
			try:
				self.debug = int( self.configfile.get( 'main', 'debug' ) )
			except:
				pass
			try:
				self.pinlenght = int( self.configfile.get( 'main', 'pinlenght' ) )
			except:
				pass
			try:
				self.secretlenght = int( self.configfile.get( 'main', 'secretlenght' ) )
			except:
				pass
		except:
			import traceback
			self.log.log( 'ERR: Something is wrong with configfile: %s Traceback: %s' % ( 
																										self.config, str( traceback.format_exc() ) ) )




		#
		# commandline parsing
		# ####################
		if self.cloptions.backend:
			self.backend = self.cloptions.backend
		if self.cloptions.timemargin:
			self.timemargin = self.cloptions.timemargin
		if self.cloptions.salt:
			self.salt = self.cloptions.salt
		if self.cloptions.set:
			import os
			if len( self.clargs ) > 0:
				self.set = self.clargs[0]
			else:
				import getpass
				self.set = getpass.getuser()
		if self.cloptions.debug:
			self.debug = self.cloptions.debug

		#
		# debugging
		# ##########
		self.log.set_debug_level( self.debug )
		self.log.debug( 'LOG: configfile: [%s]' % self.config, 10 )
		self.log.debug( 'LOG: backend: [%s]' % self.backend, 10 )
		self.log.debug( 'LOG: timemargin: [%d]' % self.timemargin, 10 )
		self.log.debug( 'LOG: salt: [%s]' % self.salt, 10 )
		self.log.debug( 'LOG: debug: [%d]' % self.debug, 10 )


	def get( self, section, option ):
		'''
			Expose the config file parser get to the backend
		'''
		return self.configfile.get( section, option )

class log( object ):
	'''
		Log object provides logging facility to syslog
	'''
	def __init__( self, debug = None ):
		self.debug_level = debug or 0
	def set_debug_level( self, level ):
		self.debug_level = int( level )
	def log( self, msg ):
		try:
			import syslog
			syslog.openlog( facility = syslog.LOG_AUTH )
			syslog.syslog( msg )
			syslog.closelog()
		except:
			print( msg )
	def debug( self, msg, weight ):
		if int( self.debug_level ) >= int( weight ):
			try:
				import syslog
				syslog.openlog( facility = syslog.LOG_AUTH )
				syslog.syslog( 'DEBUG: %s' % str( msg ) )
				syslog.closelog()
			except:
				print( 'DEBUG: %s' % str( msg ) )

class crypt( object ):
	def __init__( self, secret ):
		#
		# Based on http://www.turnkeylinux.org/blog/python-symmetric-encryption
		# ############################
		self.secret = secret
	def encrypt( self, plaintext ):
		from Crypto.Cipher import AES
		encobj = AES.new( self.secret, AES.MODE_CFB )
		ciphertext = encobj.encrypt( plaintext )
		return ciphertext

	def decrypt( self, ciphertext ):
		from Crypto.Cipher import AES
		encobj = AES.new( self.secret, AES.MODE_CFB )
		plaintext = encobj.decrypt( ciphertext )
		return plaintext





class validateMotp( object ):
	'''
		Validating object
	'''
	def __init__( self, config, username, otp ):
		import sys
		import os
		self.config = config
		self.log = self.config.log
		self.backend = self.config.backend
		self.username = username
		self.otp = otp
		self.log.debug( 'username: [%s]' % self.username, 5 )
		self.crypt = crypt( self.config.salt )

		#
		# Import backend
		# ###############
		try:
			exec( 'from %s import userInfo' % self.backend )
		except:
			import traceback
			self.log.log( "ERR: Can't load the %s backend! Traceback: %s" % ( 
																								str( self.backend ),
																								str( traceback.format_exc() ) ) )
			sys.exit( 10 )


		try:
			self.ui = userInfo( self.config, self.username )
		except:
			import traceback
			self.log.log( "ERR: Can't find userInfo object! Traceback: %s" % ( 
																								str( traceback.format_exc() ) ) )
			sys.exit( 12 )






	def validate( self ):
		'''
			Do the validating
		'''
		userinfo = self.ui.getInfo()
		if userinfo['pin'] == None:
			#
			# No info about the user
			# #######################
			self.log.log( 'WARN: No auth data for user %s' % self.username )
			return False


		#
		# Calculate time window
		# ######################
		import datetime
		timefrom = int( ( datetime.datetime.now() + \
				datetime.timedelta( seconds = userinfo['offset'] * 60 * 60 ) - \
				datetime.timedelta( seconds = self.config.timemargin * 60 ) ).strftime( '%s' )[:-1] )
		totime = int( timefrom ) + ( self.config.timemargin * 2 * 6 )


		#
		# Check if there was that MOTP already
		# #####################################
		lastotps = self.ui.getLastOtps()
		self.log.debug( 'lastotps: %s' % str( lastotps ), 10 )
		if lastotps:
			if lastotps.count( self.otp ):
				self.log.log( '%s user authentication for MOTP failed because already used valid MOTP!' % self.username )
				return False


		#
		# Try all possible code in the time window
		# #########################################
		ui_secret = self.crypt.decrypt( userinfo['secret'] )
		ui_pin = self.crypt.decrypt( userinfo['pin'] )
		import hashlib
		for n in range( timefrom, totime ):
			vhash = str( n ) + ui_secret + ui_pin
			otp = hashlib.md5( vhash ).hexdigest()[:6]
			if otp == self.otp:
				#
				# Match
				# ######
				self.ui.setLastOtp( otp )
				self.log.log( '%s user authentication for MOTP succeeded!' % self.username )
				return True
		#
		# No match
		# #########
		self.log.log( '%s user authentication for MOTP failed!' % self.username )
		return False




class setupUserInfo( object ):
	def __init__( self, config, username ):
		'''
			Set up the user pin, secret and offset
		'''
		self.config = config
		self.log = self.config.log
		self.log.debug( 'DEBUG: setupUserInfo', 4 )
		self.backend = self.config.backend
		self.username = username
		self.crypt = crypt( self.config.salt )



		#
		# Import backend
		# ###############
		try:
			exec( 'from %s import userInfo' % self.backend )
		except:
			import traceback
			import sys
			self.log.log( "ERR: Can't load the %s backend! Traceback: %s" % ( 
																								str( self.backend ),
																								str( traceback.format_exc() ) ) )
			print str( traceback.format_exc() )
			sys.exit( 10 )

		self.ui = userInfo( self.config, self.username )

		#
		# Check if there is an existing db for the user
		# ##############################################
		userinfo = self.ui.getInfo()
		if userinfo['pin'] != None:
			#
			# There is and we need to get an valid MOTP before change
			# ########################################################
			if self.ui.isValidDbForUser():
				import getpass
				votp = getpass.getpass( 'MOTP: ' )
				if not validateMotp( cfg, vusername, votp ).validate():
					print( 'MOTP not valid!' )
					import sys
					sys.exit( 13 )



	def setInfo( self ):
		'''
			Properly set the motp database of the user
		'''

		#
		# Get the pin code
		# #################
		import getpass
		print( 'PIN code must be %s lenght!' % str( self.config.pinlenght ) )
		pin1 = getpass.getpass( 'PIN: ' )
		if len( pin1 ) != self.config.pinlenght:
			print( 'Wrong PIN lenght!' )
			sys.exit( 17 )
		pin2 = getpass.getpass( 'PIN re-enter: ' )
		if pin1 != pin2:
			print( 'The two PIN are not equal!' )
			sys.exit( 14 )
		pin1 = self.crypt.encrypt( pin1 )
		self.log.debug( 'pin1: %s' % pin1, 10 )


		#
		# Get the secret code - empty -- not changed
		# ###########################################
		print( 'Secret code will appear in display as you type. Leave empty if not changed' )
		print( 'Secret code (%s character):' % str( self.config.secretlenght ) )
		secret = str( sys.stdin.readline() )[:-1]
		if len( secret ) == 0:
			secret = None
		elif len( secret ) != self.config.secretlenght:
			print( 'Secret code must have %s characters' % self.config.secretlenght )
			sys.exit( 16 )
		else:
			secret = self.crypt.encrypt( secret )


		#
		# Get the time offset - empty -- not changed
		# ###########################################
		print( 'Time offset in hour:' )
		try:
			offset = str( sys.stdin.readline() )[:-1]
			if len( offset ) == 0:
				offset = None
			else:
				offset = int( offset )
		except:
			print( 'Only decimal numbers!' )
			sys.exit( 15 )


		#
		# Ask the backend to write down the data
		# #######################################
		if self.ui.setUserInfo( pin1 , secret , offset ):
			print( 'MOTP is set or changed!' )
			self.log.log( 'MOTP is changed for the user %s' % self.username )
		else:
			print ( "MOTP can't be set! Check auth.log." )
#	
# Main
# #####

if __name__ == '__main__':
	import sys
	log = log( debug = 0 )
	cfg = config( log )



	if not cfg.set:
		#
		# We are authenticating
		# ######################
		try:
			import os
			vusername = os.environ['PAM_USER']
			log.debug( 'Username: [%s]' % vusername, 5 )
		except KeyError:
			log.log( 'PAM_USER environment variable is not set!' )
			sys.exit( 11 )
		votp = sys.stdin.readline()[:-1]
		log.debug( 'OTP: [%s]' % votp, 5 )

		if validateMotp( cfg, vusername, votp ).validate():
			#
			# Successfull
			# ############
			sys.exit( 0 )
		else:
			#
			# Failed
			# #######
			sys.exit( 1 )




	else:
		#
		# We are setting the user auth info
		# ##################################
		import os
		vusername = cfg.set
		setupUserInfo( cfg, vusername ).setInfo()
