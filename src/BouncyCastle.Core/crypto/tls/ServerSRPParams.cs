using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class ServerSRPParams
	{
		protected internal BigInteger N, g, B;
		protected internal byte[] s;

		public ServerSRPParams(BigInteger N, BigInteger g, byte[] s, BigInteger B)
		{
			this.N = N;
			this.g = g;
			this.s = Arrays.clone(s);
			this.B = B;
		}

		public virtual BigInteger getB()
		{
			return B;
		}

		public virtual BigInteger getG()
		{
			return g;
		}

		public virtual BigInteger getN()
		{
			return N;
		}

		public virtual byte[] getS()
		{
			return s;
		}

		/// <summary>
		/// Encode this <seealso cref="ServerSRPParams"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsSRPUtils.writeSRPParameter(N, output);
			TlsSRPUtils.writeSRPParameter(g, output);
			TlsUtils.writeOpaque8(s, output);
			TlsSRPUtils.writeSRPParameter(B, output);
		}

		/// <summary>
		/// Parse a <seealso cref="ServerSRPParams"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="ServerSRPParams"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static ServerSRPParams parse(InputStream input)
		{
			BigInteger N = TlsSRPUtils.readSRPParameter(input);
			BigInteger g = TlsSRPUtils.readSRPParameter(input);
			byte[] s = TlsUtils.readOpaque8(input);
			BigInteger B = TlsSRPUtils.readSRPParameter(input);

			return new ServerSRPParams(N, g, s, B);
		}
	}

}