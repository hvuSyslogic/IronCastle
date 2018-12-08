using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public class NewSessionTicket
	{
		protected internal long ticketLifetimeHint;
		protected internal byte[] ticket;

		public NewSessionTicket(long ticketLifetimeHint, byte[] ticket)
		{
			this.ticketLifetimeHint = ticketLifetimeHint;
			this.ticket = ticket;
		}

		public virtual long getTicketLifetimeHint()
		{
			return ticketLifetimeHint;
		}

		public virtual byte[] getTicket()
		{
			return ticket;
		}

		/// <summary>
		/// Encode this <seealso cref="NewSessionTicket"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsUtils.writeUint32(ticketLifetimeHint, output);
			TlsUtils.writeOpaque16(ticket, output);
		}

		/// <summary>
		/// Parse a <seealso cref="NewSessionTicket"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input"> the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="NewSessionTicket"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static NewSessionTicket parse(InputStream input)
		{
			long ticketLifetimeHint = TlsUtils.readUint32(input);
			byte[] ticket = TlsUtils.readOpaque16(input);
			return new NewSessionTicket(ticketLifetimeHint, ticket);
		}
	}

}