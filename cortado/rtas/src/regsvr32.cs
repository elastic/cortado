using System;
using System.Net.Sockets;

class Seat
{
    static void Main()
    {
        using(TcpClient tcpClient = new TcpClient())
        {
            try {
                tcpClient.Connect("8.8.8.8", 443);
                Console.WriteLine("Port open");
            } catch (Exception) {
                Console.WriteLine("Port closed");
            }
        }
    }
}