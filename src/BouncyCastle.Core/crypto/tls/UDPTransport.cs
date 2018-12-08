using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	public class UDPTransport : DatagramTransport
	{
		protected internal const int MIN_IP_OVERHEAD = 20;
		protected internal static readonly int MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64;
		protected internal const int UDP_OVERHEAD = 8;

		protected internal readonly DatagramSocket socket;
		protected internal readonly int receiveLimit, sendLimit;

		public UDPTransport(DatagramSocket socket, int mtu)
		{
			if (!socket.isBound() || !socket.isConnected())
			{
				throw new IllegalArgumentException("'socket' must be bound and connected");
			}

			this.socket = socket;

			// NOTE: As of JDK 1.6, can use NetworkInterface.getMTU

			this.receiveLimit = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD;
			this.sendLimit = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD;
		}

		public virtual int getReceiveLimit()
		{
			return receiveLimit;
		}

		public virtual int getSendLimit()
		{
			// TODO[DTLS] Implement Path-MTU discovery?
			return sendLimit;
		}

		public virtual int receive(byte[] buf, int off, int len, int waitMillis)
		{
			socket.setSoTimeout(waitMillis);
			DatagramPacket packet = new DatagramPacket(buf, off, len);
			socket.receive(packet);
			return packet.getLength();
		}

		public virtual void send(byte[] buf, int off, int len)
		{
			if (len > getSendLimit())
			{
				/*
				 * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
				 * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
				 * which will be fragmented."
				 */
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			DatagramPacket packet = new DatagramPacket(buf, off, len);
			socket.send(packet);
		}

		public virtual void close()
		{
			socket.close();
		}
	}

}