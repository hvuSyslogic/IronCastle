namespace org.bouncycastle.pkcs
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ContentInfo = org.bouncycastle.asn1.pkcs.ContentInfo;
	using MacData = org.bouncycastle.asn1.pkcs.MacData;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using Pfx = org.bouncycastle.asn1.pkcs.Pfx;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A holding class for the PKCS12 Pfx structure.
	/// </summary>
	public class PKCS12PfxPdu
	{
		private Pfx pfx;

		private static Pfx parseBytes(byte[] pfxEncoding)
		{
			try
			{
				return Pfx.getInstance(ASN1Primitive.fromByteArray(pfxEncoding));
			}
			catch (ClassCastException e)
			{
				throw new PKCSIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new PKCSIOException("malformed data: " + e.getMessage(), e);
			}
		}

		public PKCS12PfxPdu(Pfx pfx)
		{
			this.pfx = pfx;
		}

		public PKCS12PfxPdu(byte[] pfx) : this(parseBytes(pfx))
		{
		}

		/// <summary>
		/// Return the content infos in the AuthenticatedSafe contained in this Pfx.
		/// </summary>
		/// <returns> an array of ContentInfo. </returns>
		public virtual ContentInfo[] getContentInfos()
		{
			ASN1Sequence seq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(this.pfx.getAuthSafe().getContent()).getOctets());
			ContentInfo[] content = new ContentInfo[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				content[i] = ContentInfo.getInstance(seq.getObjectAt(i));
			}

			return content;
		}

		/// <summary>
		/// Return whether or not there is MAC attached to this file.
		/// </summary>
		/// <returns> true if there is, false otherwise. </returns>
		public virtual bool hasMac()
		{
			return pfx.getMacData() != null;
		}

		/// <summary>
		/// Return the algorithm identifier describing the MAC algorithm
		/// </summary>
		/// <returns> the AlgorithmIdentifier representing the MAC algorithm, null if none present. </returns>
		public virtual AlgorithmIdentifier getMacAlgorithmID()
		{
			MacData md = pfx.getMacData();

			if (md != null)
			{
				return md.getMac().getAlgorithmId();
			}

			return null;
		}

		/// <summary>
		/// Verify the MacData attached to the PFX is consistent with what is expected.
		/// </summary>
		/// <param name="macCalcProviderBuilder"> provider builder for the calculator for the MAC </param>
		/// <param name="password"> password to use </param>
		/// <returns> true if mac data is valid, false otherwise. </returns>
		/// <exception cref="PKCSException"> if there is a problem evaluating the MAC. </exception>
		/// <exception cref="IllegalStateException"> if no MAC is actually present </exception>
		public virtual bool isMacValid(PKCS12MacCalculatorBuilderProvider macCalcProviderBuilder, char[] password)
		{
			if (hasMac())
			{
				MacData pfxmData = pfx.getMacData();
				MacDataGenerator mdGen = new MacDataGenerator(macCalcProviderBuilder.get(new AlgorithmIdentifier(pfxmData.getMac().getAlgorithmId().getAlgorithm(), new PKCS12PBEParams(pfxmData.getSalt(), pfxmData.getIterationCount().intValue()))));

				try
				{
					MacData mData = mdGen.build(password, ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets());

					return Arrays.constantTimeAreEqual(mData.getEncoded(), pfx.getMacData().getEncoded());
				}
				catch (IOException e)
				{
					throw new PKCSException("unable to process AuthSafe: " + e.Message);
				}
			}

			throw new IllegalStateException("no MAC present on PFX");
		}

		/// <summary>
		/// Return the underlying ASN.1 object.
		/// </summary>
		/// <returns> a Pfx object. </returns>
		public virtual Pfx toASN1Structure()
		{
			return pfx;
		}

		public virtual byte[] getEncoded()
		{
			return toASN1Structure().getEncoded();
		}

		/// <summary>
		/// Return a Pfx with the outer wrapper encoded as asked for. For example, Pfx is a usually
		/// a BER encoded object, to get one with DefiniteLength encoding use:
		/// <pre>
		/// getEncoded(ASN1Encoding.DL)
		/// </pre> </summary>
		/// <param name="encoding"> encoding style (ASN1Encoding.DER, ASN1Encoding.DL, ASN1Encoding.BER) </param>
		/// <returns> a byte array containing the encoded object. </returns>
		/// <exception cref="IOException"> </exception>
		public virtual byte[] getEncoded(string encoding)
		{
			return toASN1Structure().getEncoded(encoding);
		}
	}

}