namespace org.bouncycastle.cert
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	/// <summary>
	/// General utility class for creating calculated extensions using the standard methods.
	/// <para>
	/// <b>Note:</b> This class is not thread safe!
	/// </para>
	/// </summary>
	public class X509ExtensionUtils
	{
		private DigestCalculator calculator;

		/// <summary>
		/// Base constructor - for conformance to RFC 5280 use a calculator based on SHA-1.
		/// </summary>
		/// <param name="calculator">  a calculator for calculating subject key ids. </param>
		public X509ExtensionUtils(DigestCalculator calculator)
		{
			this.calculator = calculator;
		}

		/// <summary>
		/// Create an AuthorityKeyIdentifier from the passed in arguments.
		/// </summary>
		/// <param name="certHolder"> the issuer certificate that the AuthorityKeyIdentifier should refer to. </param>
		/// <returns> an AuthorityKeyIdentifier. </returns>
		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(X509CertificateHolder certHolder)
		{
			GeneralName genName = new GeneralName(certHolder.getIssuer());

			return new AuthorityKeyIdentifier(getSubjectKeyIdentifier(certHolder), new GeneralNames(genName), certHolder.getSerialNumber());
		}

		/// <summary>
		/// Create an AuthorityKeyIdentifier from the passed in SubjectPublicKeyInfo.
		/// </summary>
		/// <param name="publicKeyInfo"> the SubjectPublicKeyInfo to base the key identifier on. </param>
		/// <returns> an AuthorityKeyIdentifier. </returns>
		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
		{
			return new AuthorityKeyIdentifier(calculateIdentifier(publicKeyInfo));
		}

		/// <summary>
		/// Create an AuthorityKeyIdentifier from the passed in arguments.
		/// </summary>
		/// <param name="publicKeyInfo"> the SubjectPublicKeyInfo to base the key identifier on. </param>
		/// <param name="generalNames"> the general names to associate with the issuer cert's issuer. </param>
		/// <param name="serial"> the serial number of the issuer cert. </param>
		/// <returns> an AuthorityKeyIdentifier. </returns>
		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo, GeneralNames generalNames, BigInteger serial)
		{
			return new AuthorityKeyIdentifier(calculateIdentifier(publicKeyInfo), generalNames, serial);
		}

		/// <summary>
		/// Return a RFC 5280 type 1 key identifier. As in:
		/// <pre>
		/// (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		/// value of the BIT STRING subjectPublicKey (excluding the tag,
		/// length, and number of unused bits).
		/// </pre> </summary>
		/// <param name="publicKeyInfo"> the key info object containing the subjectPublicKey field. </param>
		/// <returns> the key identifier. </returns>
		public virtual SubjectKeyIdentifier createSubjectKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
		{
			return new SubjectKeyIdentifier(calculateIdentifier(publicKeyInfo));
		}

		/// <summary>
		/// Return a RFC 5280 type 2 key identifier. As in:
		/// <pre>
		/// (2) The keyIdentifier is composed of a four bit type field with
		/// the value 0100 followed by the least significant 60 bits of the
		/// SHA-1 hash of the value of the BIT STRING subjectPublicKey.
		/// </pre> </summary>
		/// <param name="publicKeyInfo"> the key info object containing the subjectPublicKey field. </param>
		/// <returns> the key identifier. </returns>
		public virtual SubjectKeyIdentifier createTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
		{
			byte[] digest = calculateIdentifier(publicKeyInfo);
			byte[] id = new byte[8];

			JavaSystem.arraycopy(digest, digest.Length - 8, id, 0, id.Length);

			id[0] &= 0x0f;
			id[0] |= 0x40;

			return new SubjectKeyIdentifier(id);
		}

		private byte[] getSubjectKeyIdentifier(X509CertificateHolder certHolder)
		{
			if (certHolder.getVersionNumber() != 3)
			{
				return calculateIdentifier(certHolder.getSubjectPublicKeyInfo());
			}
			else
			{
				Extension ext = certHolder.getExtension(Extension.subjectKeyIdentifier);

				if (ext != null)
				{
					return ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();
				}
				else
				{
					return calculateIdentifier(certHolder.getSubjectPublicKeyInfo());
				}
			}
		}

		private byte[] calculateIdentifier(SubjectPublicKeyInfo publicKeyInfo)
		{
			byte[] bytes = publicKeyInfo.getPublicKeyData().getBytes();

			OutputStream cOut = calculator.getOutputStream();

			try
			{
				cOut.write(bytes);

				cOut.close();
			}
			catch (IOException e)
			{ // it's hard to imagine this happening, but yes it does!
				throw new CertRuntimeException("unable to calculate identifier: " + e.Message, e);
			}

			return calculator.getDigest();
		}
	}

}