using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// RFC 5246 7.4.1.4.1
	/// </summary>
	public class SignatureAndHashAlgorithm
	{
		protected internal short hash;
		protected internal short signature;

		/// <param name="hash">      <seealso cref="HashAlgorithm"/> </param>
		/// <param name="signature"> <seealso cref="SignatureAlgorithm"/> </param>
		public SignatureAndHashAlgorithm(short hash, short signature)
		{
			if (!TlsUtils.isValidUint8(hash))
			{
				throw new IllegalArgumentException("'hash' should be a uint8");
			}
			if (!TlsUtils.isValidUint8(signature))
			{
				throw new IllegalArgumentException("'signature' should be a uint8");
			}
			if (signature == SignatureAlgorithm.anonymous)
			{
				throw new IllegalArgumentException(@"'signature' MUST NOT be ""anonymous""");
			}

			this.hash = hash;
			this.signature = signature;
		}

		/// <returns> <seealso cref="HashAlgorithm"/> </returns>
		public virtual short getHash()
		{
			return hash;
		}

		/// <returns> <seealso cref="SignatureAlgorithm"/> </returns>
		public virtual short getSignature()
		{
			return signature;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is SignatureAndHashAlgorithm))
			{
				return false;
			}
			SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm)obj;
			return other.getHash() == getHash() && other.getSignature() == getSignature();
		}

		public override int GetHashCode()
		{
			return (getHash() << 16) | getSignature();
		}

		/// <summary>
		/// Encode this <seealso cref="SignatureAndHashAlgorithm"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsUtils.writeUint8(getHash(), output);
			TlsUtils.writeUint8(getSignature(), output);
		}

		/// <summary>
		/// Parse a <seealso cref="SignatureAndHashAlgorithm"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input"> the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="SignatureAndHashAlgorithm"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static SignatureAndHashAlgorithm parse(InputStream input)
		{
			short hash = TlsUtils.readUint8(input);
			short signature = TlsUtils.readUint8(input);
			return new SignatureAndHashAlgorithm(hash, signature);
		}
	}

}