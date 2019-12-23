# CSE_310_Pcap_analysis_pp3
Analyzing a pcap file


Part A

i) The pcap tcp code I made has a class called Flow that defines an object
flow to track all the tcp connections made between the same sorce and destination ports.

ii) To run my code, just run the python file after downloading the zip file that has the pcap file

	"Python analysis_pcap_tcp.py"
 
iii) How I estimate each value
    For Number of TCP flows:
         I go through each packet and parse the tcp connections then I go ahead and check if both
	the flags for SYN and ACK are set. If they are it means there is a new connections that would lead
	me to increment the number of flow counts.
      
        Based on my analysis I have figured out that there are 3 flows.
	
    For the first two transactions after the TCP connection is set up from the sender to receiver
	I get the values of Sequence number, ack number and receive window size by parsing the tcp packet. I also
	use the packet from dpkt like tcp.seq, tcp.ack, tcp.win to get the exact values
   
    The way I compute the through put is by adding the length of each packets payload in bytes and dividing them with
    the period or timestamp it took to deliever the first byte to receving the final ACK. I have a method called through
    put that takes a flow object and calculates it using the algorithm explained above howeverm, I don't count the lost packets 

    Lost packets: I have a function call Loss(flow) that takes a flow and calculates the loss rate. I calculate it by
    counting the retransimtted packets and dividing them by the total packet sent.

Part B

The congestion window size and computation of retransmissions due to duplicate acks and timeout
 Estimation of initial congestion window size and look at it's variation. 
 Extract retransmissions and segregate them in two parts. The first being
 based on triple duplicate acks and the seond one based on timeout.
 	
MY results are as shown below
 
Number of Tcp flows initiated from the sender = 3 

Flow #1
***--------------------------------------------------------------***

First two transactions after establishing TCP connection
Transaction # 1   
		sequence number:-  705669103 
		ack number:-  1921750144 
		window size:-  3
Transaction # 2   
		sequence number:-  705669127 
		ack number:-  1921750144 
		window size:-  3

Throughput = 41.06700681518265 MegaBit/second

Loss Rate = 0.0005733123118818977

Triple Acknowledgement Loss = 2 

Timeout Loss = 2

The first 5 congestion window sizes

Congestion_Window : 18980  

Congestion_Window : 29200  

Congestion_Window : 59860  

Congestion_Window : 70080  

Congestion_Window : 102200  

Congestion_Window : 154760  




Flow #2
***--------------------------------------------------------------***

First two transactions after establishing TCP connection
Transaction # 1   
		sequence number:-  3636173852 
		ack number:-  2335809728 
		window size:-  3
Transaction # 2   
		sequence number:-  3636173876 
		ack number:-  2335809728 
		window size:-  3

Throughput = 10.052268398325287 MegaBit/second

Loss Rate = 0.013440860215053764

Triple Acknowledgement Loss = 36 

Timeout Loss = 59

The first 5 congestion window sizes

Congestion_Window : 16060  

Congestion_Window : 42340  

Congestion_Window : 64240  

Congestion_Window : 71540  

Congestion_Window : 106580  

Congestion_Window : 143080  




Flow #3
***--------------------------------------------------------------***

First two transactions after establishing TCP connection
Transaction # 1   
		sequence number:-  2558634630 
		ack number:-  3429921723 
		window size:-  3
Transaction # 2   
		sequence number:-  2558634654 
		ack number:-  3429921723 
		window size:-  3

Throughput = 11.58376155758086 MegaBit/second

Loss Rate = 0.0013717421124828531

Triple Acknowledgement Loss = 0 

Timeout Loss = 1

The first 5 congestion window sizes

Congestion_Window : 18980  

Congestion_Window : 37960  

Congestion_Window : 54020  

Congestion_Window : 74460  

Congestion_Window : 110960  

Congestion_Window : 124100  


