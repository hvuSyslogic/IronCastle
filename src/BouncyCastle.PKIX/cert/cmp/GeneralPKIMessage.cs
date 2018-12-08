namespace org.bouncycastle.cert.cmp
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using PKIBody = org.bouncycastle.asn1.cmp.PKIBody;
	using PKIHeader = org.bouncycastle.asn1.cmp.PKIHeader;
	using PKIMessage = org.bouncycastle.asn1.cmp.PKIMessage;

	/// <summary>
	/// General wrapper for a generic PKIMessage
	/// </summary>
	public class GeneralPKIMessage
	{
		private readonly PKIMessage pkiMessage;

		private static PKIMessage parseBytes(byte[] encoding)
		{
			try
			{
				return PKIMessage.getInstance(ASN1Primitive.fromByteArray(encoding));
			}
			catch (ClassCastException e)
			{
				throw new CertIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CertIOException("malformed data: " + e.getMessage(), e);
			}
		}

		/// <summary>
		/// Create a PKIMessage from the passed in bytes.
		/// </summary>
		/// <param name="encoding"> BER/DER encoding of the PKIMessage </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public GeneralPKIMessage(byte[] encoding) : this(parseBytes(encoding))
		{
		}

		/// <summary>
		/// Wrap a PKIMessage ASN.1 structure.
		/// </summary>
		/// <param name="pkiMessage"> base PKI message. </param>
		public GeneralPKIMessage(PKIMessage pkiMessage)
		{
			this.pkiMessage = pkiMessage;
		}

		public virtual PKIHeader getHeader()
		{
			return pkiMessage.getHeader();
		}

		public virtual PKIBody getBody()
		{
			return pkiMessage.getBody();
		}

		/// <summary>
		/// Return true if this message has protection bits on it. A return value of true
		/// indicates the message can be used to construct a ProtectedPKIMessage.
		/// </summary>
		/// <returns> true if message has protection, false otherwise. </returns>
		public virtual bool hasProtection()
		{
			return pkiMessage.getHeader().getProtectionAlg() != null;
		}

		public virtual PKIMessage toASN1Structure()
		{
			return pkiMessage;
		}
	}

}