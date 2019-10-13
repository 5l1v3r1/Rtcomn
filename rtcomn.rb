# # # # # # # #
#!/usr/bin/env ruby
# # # # # # #

# # # # # #
# Created November 20th 2017
# Copyright (c) 2018 Beyar.
# # # #

# # #
# Name: rtcomn.rb
# #

# RTCOMN = Ruby Take Care Of My Network
#
# The point
# It will ping the whole local adress with the cidr 24 		| CHECK
# It will get all the local ip adress 				| CHECK
# It will get all the local mac address
# It will get all the open ports of each adress
# It will get all the running services on each port
# It will be able to give each local ip adress a custom name
# It will now and then scan the adress to find any new user 	| half-CHECK - Able to use cidr 32 for dedicated search
# It will filter the traffic to certain local ip adress to see what it sends and receives
# It will be able to deauthenicate each device
# It will be able to block connections
# More to come...

# Clear
system "clear" or system "cls"

# Library
require "socket"
begin
	require "net/ping"
	rescue LoadError
	return("You need to install net-ping.")
end

# Adding colors
def c(color)
	case color
		when "black"
			@black = "\033[0;30m"        # Black
		when "red"
			@red = "\033[01;31m"         # Red
		when "green"
			@green = "\033[01;32m"       # Green
		when "yellow"
			@yellow = "\033[01;33m"      # Yellow
		when "blue"
			@blue = "\033[0;34m"         # Blue
		when "purple"
			@purple = "\033[0;35m"       # Purple
		when "cyan"
			@cyan = "\033[0;36m"         # Cyan
		when "white"
			@white = "\033[0m"	     # White
		when "grey"
			@grey = "\033[0;37m"         # Grey
	end
end

# Clearing the terminal
def c2()
	system("clear") or system ("cls")
end

# Frame the output
class Frame
	def Frame::full(input)
		len = input.length
		puts "-"*(len+2)
		puts "|"+input+"|"
		puts "-"*(len+2)
	end
	def Frame::sides(input)
		puts "|"+input+"|"
	end
	def Frame::topbottom(input)
		len = input.length
		puts "-"*(len)
		puts input
		puts "-"*(len)
	end
	def Frame::top(input)
		len = input.length
		puts "-"*(len)
		puts input
	end
	def Frame::bottom(input)
		len = input.length
		puts input
		puts "-"*(len)
	end
end

# File manager
class File
	# Create
	def File::newFile(file)
		newFile_red = "\033[01;31m"
		newFile_green = "\033[01;32m"
		newFile_white = "\033[0m"
		newFile_ss = "#{newFile_green}[+]#{newFile_white} " #SuccesS
		newFile_us = "#{newFile_red}[+]#{newFile_white} " #UnsuccesS
		newFile_reminder = "#{newFile_red}[!]#{newFile_white} "
		newFile_memory = File.open(file, "w+")
		newFile_memory.close
		puts "#{newFile_ss}Memory created!"
		newFile_memory = File.open(file, "w")
		newFile_memory.puts("testing")
		newFile_memory.close
		newFile_memory = File.open(file, "r")
			if newFile_memory.read == "testing\n"
				puts "#{newFile_ss}Memory can read & write!"
			else
				puts "#{newFile_us}Memory cannot read & write!"
			end
		newFile_memory.close
		newFile_memory = File.open(file, "w+")
		newFile_memory.close
		newFile_memory = File.open(file, "r")
			if newFile_memory.read == "" or newFile_memory.read == nil
				puts "#{newFile_ss}Memory cleaned!"
			else
				puts "#{newFile_us}Memory cleaning failed!"
			end
		newFile_memory.close
		puts "#{newFile_reminder}Path: " + Dir.pwd + "/" + file
	end
	# Read
	def File::readFile(file)
		readFile_green = "\033[01;32m"
		readFile_white = "\033[0m"
		readFile_start_quote = "#{readFile_green}[#{readFile_white}"
		readFile_end_quote = "#{readFile_green}]#{readFile_white}"
		readFile_read_file = File.open(file, "r")
		puts readFile_start_quote + readFile_read_file.read().chomp + readFile_end_quote
		readFile_read_file.close
	end
	# Write
	def File::writeFile(file, content)
		writeFile_green = "\033[01;32m"
		writeFile_white = "\033[0m"
		writeFile_info = "#{writeFile_green}[+]#{writeFile_white} "
		writeFile_read_file = File.open(file, "a")
		writeFile_read_file.write(content)
		writeFile_read_file.close
	end
end

# Interface & IP Adress detection, iip
class Detection
	def Detection::local()
		iip_ipadress = Socket.getifaddrs
		iip_ipadress.each do |iip_interface|
			if iip_interface.addr
				if iip_interface.addr.ipv4?
					@myinterface = myinterface = iip_interface.name # @myinterface will represent your interface
					@myipadress = myipadress = iip_interface.addr.ip_address # @myinterface will represent your IP adress
				end
			end
		end
		return @myinterface+":"+@myipadress
	end
end

# Scanner
class Scan

	# Ping
	def Scan::ping(host)
		check = Net::Ping::External.new(host)
		check.ping?
	end
	
	# TCP
	def Scan::tcp(host)
		check = Net::Ping::TCP.new(host)
		check.ping?
	end
	
	# UDP
	def Scan::udp(host)
		check = Net::Ping::UDP.new(host)
		check.ping?
	end
	
	# Identify range and cidr
	def Scan::identify(range, cidr)
		# CIDR = 16
		# 1.1.0.0
		#
		# CIDR  = 24
		# 1.1.1.0
		#
		# CIDR = 32
		# 1.1.1.1
		@localIP = Detection.local.split(":")[1]
		case cidr
			when 16
			first(range, @localIP)
			when 24
			second(range, @localIP)
			when 32
			third(range)
		end
	end

	# CIDR 16
	def Scan::first(range, ip)
		# Still on the drawing board
	end
	
	# CIDR 24
	def Scan::second(range, ip)
		@onlineIP = []
		@offlineIP = []
		sip = ip.split(".")
		arip = "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{sip[3]}"
		puts c("red")+"Network discovery started"+c("white")
		for each in 1..range
			Thread.new{
			if each >= 0 && each <= 9
			puts "| ARP using ICMP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}  |"
			elsif each > 9 && each <= 99
			puts "| ARP using ICMP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each} |"
			elsif each > 0 && each > 9 && each > 99
			puts "| ARP using ICMP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}|"
			end
			}
			if Scan::ping("#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}") == true
				@onlineIP << "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}"
			else
				@offlineIP << "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}"
			end
			
		end
		for each in 1..range
			Thread.new{
			if each >= 0 && each <= 9
			puts "| ARP using TCP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}   |"
			elsif each > 9 && each <= 99
			puts "| ARP using TCP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}  |"
			elsif each > 0 && each > 9 && each > 99
			puts "| ARP using TCP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each} |"
			end
			}
			if Scan::tcp("#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}") == true
				@onlineIP << "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}"
			else
				@offlineIP << "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}"
			end
			
		end
		for each in 1..range
			Thread.new{
			if each >= 0 && each <= 9
			puts "| ARP using UDP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}   |"
			elsif each > 9 && each <= 99
			puts "| ARP using UDP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}  |"
			elsif each > 0 && each > 9 && each > 99
			puts "| ARP using UDP: " + "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each} |"
			end
			}
			if Scan::udp("#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}") == true
				@onlineIP << "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}"
			else
				@offlineIP << "#{sip[0]}.#{sip[1]}.#{sip[2]}.#{each}"
			end
			
		end
		puts c("green")+"Network discovery ended"+c("white")
		puts("#{@onlineIP.uniq.count} devices found!\n#{@onlineIP.uniq.inspect}") ##{@offlineIP.uniq.count} offline devices found!\n
	end

	# CIDR 32
	def Scan::third(range)
		ping32 = 1
		tcp32 = 0
		udp32 = 0
		count = 0
		dotping = "    "
		dottcp = "    "
		dotudp = "    "
		dot = "In queue"
		finalping = ""
		finaltcp = ""
		finaludp = ""
		while ping32 == 1
			if count == 0
			dotping = "   "
			elsif count == 1
			dotping = ".  "
			elsif count == 2
			dotping = ".. "
			elsif count == 3
			dotping = "..."
			count = 0
			end
			puts "Sending ICMP packet to "+range
			puts "| Ping | " + dotping + " |"
			puts "| TCP  | " + dot + " |"
			puts "| UDP  | " + dot + " |"
			Thread.new{
			if Scan::ping(range) == true
			dotping = "reachable"
			ping32 = 0
			tcp32 = 1
			else
			dotping = "unreachable"
			ping32 = 0
			tcp32 = 1
			end
			}
			sleep(0.1)
			c2
			count += 1
		end
		dot = "In queue"
		while tcp32 == 1
			if count == 0
			dottcp = "   "
			elsif count == 1
			dottcp = ".  "
			elsif count == 2
			dottcp = ".. "
			elsif count == 3
			dottcp = "..."
			count = 0
			end
			puts "Sending TCP packet to "+range
			puts "| Ping | " + dotping + " |"
			puts "| TCP  | " + dottcp + " |"
			puts "| UDP  | " + dot + " |"
			Thread.new{
			if Scan::tcp(range) == true
			dottcp = "reachable"
			tcp32 = 0
			udp32 = 1
			else
			dottcp = "unreachable"
			tcp32 = 0
			udp32 = 1
			end
			}
			sleep(0.1)
			c2
			count += 1
		end
		dot = "In queue"
		while udp32 == 1
			if count == 0
			dotudp = "   "
			elsif count == 1
			dotudp = ".  "
			elsif count == 2
			dotudp = ".. "
			elsif count == 3
			dotudp = "..."
			count = 0
			end
			puts "Sending UDP packet to "+range
			puts "| Ping | " + dotping + " |"
			puts "| TCP  | " + dottcp + " |"
			puts "| UDP  | " + dotudp + " |"
			Thread.new{
			if Scan::udp(range) == true
			dotudp = "reachable"
			udp32 = 0
			else
			dotudp = "unreachable"
			udp32 = 0
			end
			}
			sleep(0.1)
			c2
			count += 1
		end
		puts c("yellow")+"Targeted network scan started"+c("white")
		puts "Response from "+range
		puts "| Ping | " + dotping + " |"
		puts "| TCP  | " + dottcp + " |"
		puts "| UDP  | " + dotudp + " |"
		puts c("green")+"Targeted network scan ended"+c("white")
	end
end

Scan.identify(25, 24)
#Scan.identify("192.168.0.5", 32)

# NOTE
#ip.host matches "192" && ip.src == 192.168.0.12 && (not ip.addr==83.255.255.2)  && (not ip.addr==83.255.255.1) && icmpt
#for x in 0..25
#	puts Scan.ping("192.168.0.#{x}")
#end

# NOTE: With Command ARP -a you can get all the ips and mac adresses
#system("arp -a")
