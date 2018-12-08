using System;
using System.Threading;

namespace org.bouncycastle.crypto.tls.test
{

	public class MockDatagramAssociation
	{
		private int mtu;
		private MockDatagramTransport client, server;

		public MockDatagramAssociation(int mtu)
		{
			this.mtu = mtu;

			Vector clientQueue = new Vector();
			Vector serverQueue = new Vector();

			this.client = new MockDatagramTransport(this, clientQueue, serverQueue);
			this.server = new MockDatagramTransport(this, serverQueue, clientQueue);
		}

		public virtual DatagramTransport getClient()
		{
			return client;
		}

		public virtual DatagramTransport getServer()
		{
			return server;
		}

		public class MockDatagramTransport : DatagramTransport
		{
			private readonly MockDatagramAssociation outerInstance;

			internal Vector receiveQueue, sendQueue;

			public MockDatagramTransport(MockDatagramAssociation outerInstance, Vector receiveQueue, Vector sendQueue)
			{
				this.outerInstance = outerInstance;
				this.receiveQueue = receiveQueue;
				this.sendQueue = sendQueue;
			}

			public virtual int getReceiveLimit()
			{
				return outerInstance.mtu;
			}

			public virtual int getSendLimit()
			{
				return outerInstance.mtu;
			}

			public virtual int receive(byte[] buf, int off, int len, int waitMillis)
			{
				lock (receiveQueue)
				{
					if (receiveQueue.isEmpty())
					{
						try
						{
							Monitor.Wait(receiveQueue, TimeSpan.FromMilliseconds(waitMillis));
						}
						catch (InterruptedException)
						{
							// TODO Keep waiting until full wait expired?
						}
						if (receiveQueue.isEmpty())
						{
							return -1;
						}
					}
					DatagramPacket packet = (DatagramPacket)receiveQueue.remove(0);
					int copyLength = Math.Min(len, packet.getLength());
					JavaSystem.arraycopy(packet.getData(), packet.getOffset(), buf, off, copyLength);
					return copyLength;
				}
			}

			public virtual void send(byte[] buf, int off, int len)
			{
				if (len > outerInstance.mtu)
				{
					// TODO Simulate rejection?
				}

				byte[] copy = new byte[len];
				JavaSystem.arraycopy(buf, off, copy, 0, len);
				DatagramPacket packet = new DatagramPacket(copy, len);

				lock (sendQueue)
				{
					sendQueue.addElement(packet);
					Monitor.Pulse(sendQueue);
				}
			}

			public virtual void close()
			{
				// TODO?
			}
		}
	}

}