# Rtcomn
A network tool written in Ruby with the intent to scan the whole network, identify each connected device and store them for later usage.

# The process
Rtcomn works by pinging each ip adress in a specific range you provide.
![Demo image one](https://raw.githubusercontent.com/Beyarz/rtcomn.rb/master/img/image_one.png)

What happens in the background is that you're checking if there is any device assigned to the ip adress.
![Demo image two](https://raw.githubusercontent.com/Beyarz/rtcomn.rb/master/img/image_two.png)

Rtcomn uses different techniques such as sending UDP pings (Pings to UDP port).
![Demo image three](https://raw.githubusercontent.com/Beyarz/rtcomn.rb/master/img/image_three.png)

So far, this tool has been pretty reliable to me by providing the right results 98% of the times.
![Demo image four](https://raw.githubusercontent.com/Beyarz/rtcomn.rb/master/img/image_four.png)
![Demo image five](https://raw.githubusercontent.com/Beyarz/rtcomn.rb/master/img/image_five.png)

# Stuff to keep in mind
Speed & performance is not something this tool guarantees.
Reliability is not something I promise either, see this tool as experimental.
