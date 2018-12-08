namespace org.bouncycastle.crypto.tls.test
{

	public class UnreliableDatagramTransport : DatagramTransport
	{

		private readonly DatagramTransport transport;
		private readonly Random random;
		private readonly int percentPacketLossReceiving, percentPacketLossSending;

		public UnreliableDatagramTransport(DatagramTransport transport, Random random, int percentPacketLossReceiving, int percentPacketLossSending)
		{
			if (percentPacketLossReceiving < 0 || percentPacketLossReceiving > 100)
			{
				throw new IllegalArgumentException("'percentPacketLossReceiving' out of range");
			}
			if (percentPacketLossSending < 0 || percentPacketLossSending > 100)
			{
				throw new IllegalArgumentException("'percentPacketLossSending' out of range");
			}

			this.transport = transport;
			this.random = random;
			this.percentPacketLossReceiving = percentPacketLossReceiving;
			this.percentPacketLossSending = percentPacketLossSending;
		}

		public virtual int getReceiveLimit()
		{
			return transport.getReceiveLimit();
		}

		public virtual int getSendLimit()
		{
			return transport.getSendLimit();
		}

		public virtual int receive(byte[] buf, int off, int len, int waitMillis)
		{
			long endMillis = System.currentTimeMillis() + waitMillis;
			for (; ;)
			{
				int length = transport.receive(buf, off, len, waitMillis);
				if (length < 0 || !lostPacket(percentPacketLossReceiving))
				{
					return length;
				}

				JavaSystem.@out.println("PACKET LOSS (" + length + " byte packet not received)");

				long now = System.currentTimeMillis();
				if (now >= endMillis)
				{
					return -1;
				}

				waitMillis = (int)(endMillis - now);
			}
		}

		public virtual void send(byte[] buf, int off, int len)
		{
			if (lostPacket(percentPacketLossSending))
			{
				JavaSystem.@out.println("PACKET LOSS (" + len + " byte packet not sent)");
			}
			else
			{
				transport.send(buf, off, len);
			}
		}

		public virtual void close()
		{
			transport.close();
		}

		private bool lostPacket(int percentPacketLoss)
		{
			return percentPacketLoss > 0 && random.nextInt(100) < percentPacketLoss;
		}
	}

}