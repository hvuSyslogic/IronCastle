using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	public class DigitallySigned
	{
		protected internal SignatureAndHashAlgorithm algorithm;
		protected internal byte[] signature;

		public DigitallySigned(SignatureAndHashAlgorithm algorithm, byte[] signature)
		{
			if (signature == null)
			{
				throw new IllegalArgumentException("'signature' cannot be null");
			}

			this.algorithm = algorithm;
			this.signature = signature;
		}

		/// <returns> a <seealso cref="SignatureAndHashAlgorithm"/> (or null before TLS 1.2). </returns>
		public virtual SignatureAndHashAlgorithm getAlgorithm()
		{
			return algorithm;
		}

		public virtual byte[] getSignature()
		{
			return signature;
		}

		/// <summary>
		/// Encode this <seealso cref="DigitallySigned"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			if (algorithm != null)
			{
				algorithm.encode(output);
			}
			TlsUtils.writeOpaque16(signature, output);
		}

		/// <summary>
		/// Parse a <seealso cref="DigitallySigned"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="context">
		///            the <seealso cref="TlsContext"/> of the current connection. </param>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="DigitallySigned"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static DigitallySigned parse(TlsContext context, InputStream input)
		{
			SignatureAndHashAlgorithm algorithm = null;
			if (TlsUtils.isTLSv12(context))
			{
				algorithm = SignatureAndHashAlgorithm.parse(input);
			}
			byte[] signature = TlsUtils.readOpaque16(input);
			return new DigitallySigned(algorithm, signature);
		}
	}

}